// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, deterministic, secret-free config snapshot export (issue #43).
//!
//! A snapshot is the promotable configuration of ONE environment, serialized to a
//! canonical JSON document. It is the substrate the config-promotion flagship
//! builds on: the promotion engine (5.4) diffs and applies snapshots, the
//! Terraform provider and CLI (5.11) consume the format, and a snapshot committed
//! to a git repository makes an environment's config diffable and reviewable in
//! ordinary code review. Two properties make that possible, and this module
//! guarantees both by construction:
//!
//! - **Deterministic / canonical.** Two exports of the same configuration produce
//!   BYTE-IDENTICAL output. Object keys are recursively sorted, arrays are ordered
//!   by a stable natural key (a client's `client_id`, a resource server's
//!   `audience`, a policy's `name`), and NO timestamp, counter, row insertion
//!   order, or other volatile field ever enters the document. Nothing is drawn
//!   from wall-clock time or entropy, so an export needs neither seam and is
//!   reproducible across builds and machines. See [`to_canonical_string`].
//!
//! - **Secret-free.** A snapshot carries NO secret material: no client secret (nor
//!   its stored hash), no signing private key, no management credential, no
//!   encrypted-secret ciphertext. Where a promotable resource references a secret
//!   (a confidential client's secret), the document carries a NAMED REFERENCE into
//!   the environment-scoped secret store (5.5), never the value; import resolves
//!   the reference against the TARGET environment. The export projects only the
//!   non-secret columns of each resource, so a secret cannot leak even in
//!   principle.
//!
//! The set of resource types a snapshot carries is not a hand-maintained list: it
//! is exactly the types [`crate::classification::classify`] marks
//! [`ResourceClassification::Promotable`][crate::ResourceClassification::Promotable]
//! (clients, resource servers, DCR policies today). [`SNAPSHOT_RESOURCE_TYPES`] is
//! checked against that classification by a test, so a newly promotable resource
//! type forces snapshot coverage and an environment-identity or runtime type can
//! never appear.
//!
//! # What is NOT in this module
//!
//! Per the issue's scope split, this module delivers EXPORT and validated IMPORT
//! (parse + full-document validation) only. It does NOT apply a snapshot into an
//! environment: the transactional diff/plan/apply promotion engine is issue #44,
//! and resolving a secret reference against a target environment's secret store is
//! issue #45. [`validate_document`] therefore VALIDATES-then-stops (it never
//! mutates state); the apply half is the promotion engine's.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::classification::{ResourceClassification, ResourceType, classify};
use crate::error::StoreError;
use crate::repository::ScopedStore;

/// The snapshot format version embedded in every document ([`Snapshot::schema_version`]).
///
/// A document whose version an importer does not recognize is rejected rather
/// than guessed at (fail closed). The version is bumped only on a
/// backward-incompatible change to the document shape; additive, ignorable fields
/// do not bump it.
pub const SNAPSHOT_SCHEMA_VERSION: &str = "ironauth.config-snapshot/v1";

/// The logical secret-store slot a confidential client's secret is referenced by
/// in a snapshot ([`SecretRef::reference`]). The value itself lives in the
/// environment-scoped secret store (issue #45); the snapshot names the slot, and
/// import resolves it against the TARGET environment.
pub const CLIENT_SECRET_REFERENCE: &str = "client_secret";

/// The logical secret-store slot a federation connector's UPSTREAM client secret is
/// referenced by in a snapshot ([`SecretRef::reference`]). The value itself is sealed
/// per environment (issue #48) and NEVER travels; the snapshot names the slot, and a
/// promotion resolves it against the TARGET environment (issue #75). This is the #58
/// proof that a connector's secret can never leak into an export.
pub const CONNECTOR_CLIENT_SECRET_REFERENCE: &str = "connector_client_secret";

/// The resource types a snapshot carries.
///
/// This MUST equal exactly the set [`classify`] marks
/// [`ResourceClassification::Promotable`]. The `snapshot_types_are_exactly_the_promotable_set`
/// test enforces that equality, so this constant cannot drift from the
/// classification: a new promotable type fails the test until it is covered here
/// (and by the export), and an environment-identity or runtime type can never be
/// added without failing it. This is the live binding between the snapshot and the
/// single source of truth, not a hand-maintained parallel list.
pub const SNAPSHOT_RESOURCE_TYPES: [ResourceType; 10] = [
    ResourceType::Client,
    ResourceType::ResourceServer,
    ResourceType::DcrPolicy,
    ResourceType::Variable,
    ResourceType::Connector,
    ResourceType::OrgConnection,
    ResourceType::RoutingRule,
    ResourceType::UpstreamTokenGrant,
    ResourceType::Brand,
    ResourceType::LocaleBundle,
];

/// A named reference to a secret in the environment-scoped secret store (issue
/// #45), standing in a snapshot for a secret value the document never carries.
///
/// A confidential client's secret is exported as `{"reference": "client_secret"}`,
/// not as the secret or its hash. Import resolves the reference against the TARGET
/// environment's secret store, so promoting dev to prod uses prod's secret, never
/// dev's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    /// The logical secret-store slot this reference names (for example
    /// [`CLIENT_SECRET_REFERENCE`]). Never a secret value.
    pub reference: String,
}

/// The secret-free projection of one OAuth client (issue #43).
///
/// Every field is non-secret promotable configuration. The stored secret hash,
/// the RFC 7592 registration access token hash, and the DCR-origin/quarantine
/// runtime markers are deliberately NOT projected. A confidential client carries a
/// [`SecretRef`] in [`ClientSnapshot::secret`] instead of any secret material.
//
// Each flag is an independent per-client registration attribute, not a state
// machine, exactly as on the source `ClientRecord` (which carries the same
// allow): the projection would only lose fidelity by collapsing them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    /// The client identifier: the client's public, protocol-level identity that
    /// relying parties configure. Not a secret.
    pub client_id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The registered `token_endpoint_auth_method`.
    pub token_endpoint_auth_method: String,
    /// The registered redirect URIs, sorted for a canonical order.
    pub redirect_uris: Vec<String>,
    /// The registered post-logout redirect URIs, sorted for a canonical order.
    pub post_logout_redirect_uris: Vec<String>,
    /// The registered OIDC Front-Channel Logout URI, if the client opted in.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub frontchannel_logout_uri: Option<String>,
    /// Whether `iss` and the client's own `sid` are appended to the
    /// front-channel logout URI.
    pub frontchannel_logout_session_required: bool,
    /// The client's consent mode (`explicit`, `implicit`, or `remembered`).
    pub consent_mode: String,
    /// Whether the client skips the consent screen.
    pub skip_consent: bool,
    /// Whether a skipped consent is still persisted as a consent row.
    pub store_skipped_consent: bool,
    /// Whether the client requires a pushed authorization request.
    pub require_pushed_authorization_requests: bool,
    /// Whether the client registered `require_auth_time`.
    pub require_auth_time: bool,
    /// The client's inline JWK Set (PUBLIC verification keys) for
    /// `private_key_jwt`, if registered inline. Public key material, never a
    /// private key: the export projects the stored `jwks` column to its public
    /// members with [`project_jwks_public`], stripping every private JWK parameter
    /// (so a private-bearing stored column cannot leak), and [`validate_document`]
    /// rejects any private JWK parameter that somehow remained.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jwks: Option<String>,
    /// The client's `jwks_uri`, if its verification keys are fetched rather than
    /// inline.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jwks_uri: Option<String>,
    /// The client's registered `token_endpoint_auth_signing_alg`, if it pinned one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// The client's refresh-token rotation override (`always` or `threshold`), if set.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_rotation: Option<String>,
    /// A NAMED REFERENCE to the client's secret in the environment secret store,
    /// present iff the client is confidential (has a stored secret). Never the
    /// secret or its hash. Absent for a public or JWT-assertion client.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub secret: Option<SecretRef>,
}

/// The secret-free projection of one resource server (issue #43). A resource
/// server holds no secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceServerSnapshot {
    /// The resource-server identifier / resource URI a token targets. Unique per
    /// environment, so it is the stable natural key the export orders by.
    pub audience: String,
    /// The access-token format this resource server receives (`at_jwt` or `opaque`).
    pub token_format: String,
    /// The per-resource-server access-token lifetime in seconds, or absent to fall
    /// back to the environment default.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_token_ttl_secs: Option<i64>,
}

/// The secret-free projection of one DCR policy (issue #43). A policy holds no
/// secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcrPolicySnapshot {
    /// The policy name, unique per scope: the stable natural key the export orders by.
    pub name: String,
    /// The ordered primitive list, embedded as parsed JSON (so it canonicalizes
    /// recursively, not as an opaque string with whatever whitespace was stored).
    pub primitives: serde_json::Value,
}

/// The secret-free projection of one environment variable (issue #45). A variable
/// is NON-secret promotable config (name -> value): both its name and its value
/// travel in the snapshot, so a target environment may override the value at apply
/// time. A field elsewhere in the snapshot may carry a `${var:NAME}` reference to
/// it (resolved per target environment); the variable itself is a plain value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableSnapshot {
    /// The variable name, unique per scope: the stable natural key the export
    /// orders by and the key a `${var:NAME}` reference resolves against.
    pub name: String,
    /// The non-secret configuration value. A variable value is never a secret
    /// (a secret value never appears in a snapshot at all).
    pub value: String,
}

/// The secret-free projection of one federation connector (issue #75). Its
/// `definition` is the connector's SECRET-FREE definition document (the upstream
/// client secret is stripped before it is ever stored). A confidential connector
/// carries a [`SecretRef`] in [`ConnectorSnapshot::secret`] instead of any secret
/// material: the upstream client secret's VALUE never travels, only the named
/// reference does, resolved per target environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorSnapshot {
    /// The connector slug, unique per scope: the stable natural key the export
    /// orders by.
    pub connector_slug: String,
    /// The connector's SECRET-FREE definition document (issuer or explicit
    /// endpoints, scopes, client id, PKCE mode, claim mapping, quirks, and the
    /// capability matrix). Embedded as parsed JSON so it canonicalizes recursively.
    /// The upstream `client_secret` field is NOT present.
    pub definition: serde_json::Value,
    /// Whether the connector is active.
    pub enabled: bool,
    /// A NAMED REFERENCE to the connector's upstream client secret in the
    /// environment secret store. Never the secret. Resolved against the TARGET
    /// environment on import.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub secret: Option<SecretRef>,
}

/// The secret-free projection of one organization-to-connector binding (issue #77).
/// A binding holds NO secret material: it names the organization and the connector it
/// binds (the connector's OWN upstream secret never travels; only a reference in the
/// connector projection does), the broker overlay policy (a later PR fills these), and
/// whether it captures upstream tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgConnectionSnapshot {
    /// The organization this binding belongs to.
    pub organization_id: String,
    /// The connector describing the organization's upstream. Part of the stable
    /// natural key the export orders by.
    pub connector_id: String,
    /// The broker overlay minimum acr, if set (a later PR enforces it).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overlay_min_acr: Option<String>,
    /// The broker overlay maximum authentication age in seconds, if set.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_age_secs: Option<i64>,
    /// The broker overlay minimum credential class, if set (a rung of the ladder).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overlay_min_class: Option<String>,
    /// Whether a later PR captures the upstream tokens after a brokered login.
    pub capture_upstream_tokens: bool,
    /// Whether the binding is active.
    pub enabled: bool,
}

/// The secret-free projection of one routing rule (issue #77). Exactly one selector is
/// present, matching the rule kind; a user selector is carried as an OPAQUE blind index
/// (base64), never a plaintext identifier, so the export stays free of user PII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRuleSnapshot {
    /// The selector kind (`domain`, `app`, or `user`).
    pub rule_kind: String,
    /// The normalized email domain, present iff `rule_kind` is `domain`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub domain: Option<String>,
    /// The app client id, present iff `rule_kind` is `app`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_id: Option<String>,
    /// The OPAQUE base64 blind index of the canonical login identifier, present iff
    /// `rule_kind` is `user`. Never a plaintext identifier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_bidx: Option<String>,
    /// The org connection a matching login routes to.
    pub org_connection_id: String,
    /// The evaluation priority.
    pub priority: i64,
    /// Whether the rule is active.
    pub enabled: bool,
}

/// The secret-free projection of one upstream-token retrieval grant (issue #77, PR 3):
/// the authorization config naming WHICH client may retrieve a session's captured
/// upstream tokens. It holds NO secret (the tokens themselves are Runtime and never
/// exported); only the client and org-connection references and the enabled flag travel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamTokenGrantSnapshot {
    /// The client authorized to retrieve upstream tokens. Part of the stable natural
    /// key the export orders by.
    pub client_id: String,
    /// The org connection whose sessions' tokens the client may retrieve. Part of the
    /// stable natural key the export orders by.
    pub org_connection_id: String,
    /// Whether the grant is active.
    pub enabled: bool,
}

/// The secret-free projection of one per-environment brand (issue #86). A brand is
/// NON-secret promotable branding config: the design tokens (and dark variants) and
/// the sanitized rich-text slots travel as embedded parsed JSON so they canonicalize
/// recursively, and the plain wordmark fields travel as scalars. No secret and no PII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandSnapshot {
    /// The brand slug, unique per scope: the stable natural key the export orders by.
    pub slug: String,
    /// Whether this is the environment's default brand.
    pub is_default: bool,
    /// The plain-text product name / wordmark.
    pub product_name: String,
    /// Whether to show the wordmark header.
    pub show_wordmark: bool,
    /// The optional plain-text brand-token badge.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub brand_token: Option<String>,
    /// The TYPED design tokens (a JSON object of validated scalars), embedded as parsed
    /// JSON so it canonicalizes recursively.
    pub tokens: serde_json::Value,
    /// The dark-mode token variants, if authored.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tokens_dark: Option<serde_json::Value>,
    /// The sanitized rich-text slots (a JSON object of slot key to sanitized markup),
    /// embedded as parsed JSON.
    pub slots: serde_json::Value,
}

/// The secret-free projection of one per-environment locale bundle (issue #86, PR 2). A locale
/// bundle is NON-secret promotable localization config: the BCP47 tag, the env-default flag,
/// and the entries map (numeric message id string to the plain-text render) travel as embedded
/// parsed JSON so it canonicalizes recursively. No secret and no PII: a bundle string is a
/// plain-text label, title, or error, escaped on render exactly like the compiled default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocaleBundleSnapshot {
    /// The BCP47 language tag, unique per scope: the stable natural key the export orders by.
    pub locale: String,
    /// Whether this is the environment's default locale.
    pub is_env_default: bool,
    /// The bundle entries (a JSON object of numeric message id string to the plain-text
    /// render), embedded as parsed JSON so it canonicalizes recursively.
    pub entries: serde_json::Value,
}

/// The promotable resources a snapshot carries, keyed by resource-type wire name
/// (issue #41 classification). Each array is ordered by its type's stable natural
/// key, so the collection order is deterministic and documented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SnapshotResources {
    /// The environment's OAuth clients (`client`).
    #[serde(default)]
    pub client: Vec<ClientSnapshot>,
    /// The environment's resource servers (`resource_server`).
    #[serde(default)]
    pub resource_server: Vec<ResourceServerSnapshot>,
    /// The environment's DCR policies (`dcr_policy`).
    #[serde(default)]
    pub dcr_policy: Vec<DcrPolicySnapshot>,
    /// The environment's non-secret configuration variables (`variable`). A
    /// secret value never appears here; only a variable's plain value does.
    #[serde(default)]
    pub variable: Vec<VariableSnapshot>,
    /// The environment's federation connectors (`connector`). Each carries the
    /// connector's secret-free definition and a NAMED REFERENCE to its upstream
    /// client secret, never the secret value.
    #[serde(default)]
    pub connector: Vec<ConnectorSnapshot>,
    /// The environment's organization-to-connector bindings (`org_connection`). Each
    /// is secret-free (issue #77).
    #[serde(default)]
    pub org_connection: Vec<OrgConnectionSnapshot>,
    /// The environment's routing rules (`routing_rule`). Each carries an opaque user
    /// selector, never a plaintext identifier (issue #77).
    #[serde(default)]
    pub routing_rule: Vec<RoutingRuleSnapshot>,
    /// The environment's upstream-token retrieval grants (`upstream_token_grant`). Each
    /// is secret-free authorization config; the captured tokens themselves are Runtime
    /// and never exported (issue #77, PR 3).
    #[serde(default)]
    pub upstream_token_grant: Vec<UpstreamTokenGrantSnapshot>,
    /// The environment's per-environment brands (`brand`). Each is secret-free branding
    /// config (typed design tokens and sanitized rich-text slots); per-organization
    /// branding is deferred to M10 and rides org export, never the snapshot (issue #86).
    #[serde(default)]
    pub brand: Vec<BrandSnapshot>,
    /// The environment's per-environment locale bundles (`locale_bundle`). Each is secret-free
    /// localization config (a BCP47 tag and its numeric-id to plain-text map); per-organization
    /// localization is out of scope for #86 (issue #86, PR 2).
    #[serde(default)]
    pub locale_bundle: Vec<LocaleBundleSnapshot>,
}

/// A canonical, deterministic, secret-free snapshot of one environment's
/// promotable configuration (issue #43).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The snapshot format version ([`SNAPSHOT_SCHEMA_VERSION`]).
    pub schema_version: String,
    /// The promotable resources, grouped by type.
    pub resources: SnapshotResources,
}

impl Snapshot {
    /// Serialize this snapshot to its canonical byte form (issue #43): the sole
    /// promotion-stable representation. Equal snapshots produce equal bytes.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] wrapping a serialization fault, which cannot occur
    /// for a well-formed snapshot (every field is a plain JSON-able value) and is
    /// surfaced rather than panicked on for caller robustness.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, StoreError> {
        Ok(self.to_canonical_string()?.into_bytes())
    }

    /// Serialize this snapshot to its canonical JSON string (issue #43).
    ///
    /// The canonical form is: object keys recursively sorted by Unicode code
    /// point, arrays in their stored (already deterministic) order, compact
    /// separators, and no insignificant whitespace. This is RFC 8785-aligned for
    /// the ASCII-keyed string/integer/boolean value space the document uses. The
    /// output depends only on the snapshot's content, never on struct field
    /// declaration order or `serde_json` map iteration order.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] wrapping a serialization fault (not reachable for a
    /// well-formed snapshot).
    pub fn to_canonical_string(&self) -> Result<String, StoreError> {
        let value = serde_json::to_value(self).map_err(serde_fault)?;
        let mut out = String::new();
        write_canonical(&value, &mut out);
        Ok(out)
    }
}

/// Wrap a `serde_json` fault as a store error (the store's uniform error type).
fn serde_fault(error: serde_json::Error) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(Box::new(error)))
}

/// Recursively write `value` in canonical JSON form into `out`.
///
/// Object keys are sorted (by Rust `str` order, which is Unicode code-point order
/// and coincides with RFC 8785's UTF-16 order across the ASCII key space this
/// document uses); every value is emitted with compact separators and no
/// insignificant whitespace. String escaping and integer rendering reuse
/// `serde_json`'s own scalar encoders, so they match the JSON grammar exactly.
fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        // `serde_json`'s `Number::to_string` renders integers exactly and floats via
        // ryu's shortest round-tripping form. Every number a snapshot carries is
        // integer-bounded in practice (a resource server's `access_token_ttl_secs` is
        // an `i64`; a DCR policy's embedded primitive counts are JSON integers), so
        // the output is canonical for the value space actually used. Even were a
        // float to appear, the rendering is a pure function of the parsed value, so
        // determinism (equal snapshots produce equal bytes) holds regardless.
        serde_json::Value::Number(number) => out.push_str(&number.to_string()),
        serde_json::Value::String(text) => write_json_string(text, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                // `keys` is drawn from `map`, so every lookup is present.
                if let Some(child) = map.get(*key) {
                    write_canonical(child, out);
                }
            }
            out.push('}');
        }
    }
}

/// Append `text` as a JSON string literal (quoted and escaped) to `out`, reusing
/// `serde_json`'s string encoder so the escaping matches the grammar exactly.
fn write_json_string(text: &str, out: &mut String) {
    // A `&str` always serializes; the `else` keeps the function total without a
    // panic on the unreachable path.
    if let Ok(encoded) = serde_json::to_string(text) {
        out.push_str(&encoded);
    } else {
        out.push('"');
        out.push('"');
    }
}

/// Export the promotable configuration of one environment as a canonical snapshot
/// (issue #43).
///
/// Reads every promotable resource type in `scoped`'s (tenant, environment) scope
/// through the scoped repositories, so row-level security confines the export to
/// exactly that environment's rows: a snapshot exports ONLY its own scope's
/// config, never another tenant's or environment's. The projection is secret-free
/// (see the module docs), and the resulting document is canonical and
/// deterministic.
///
/// The resource types read here are exactly [`SNAPSHOT_RESOURCE_TYPES`], the
/// classification's promotable set; environment-identity types (the environment,
/// its signing keys, its management credentials) and runtime types are never read.
///
/// # Errors
///
/// [`StoreError::Database`] on a persistence failure, or if a stored row fails to
/// decode.
// One linear export sweep (one block per promotable resource type); splitting it would
// scatter the single "read every promotable type, secret-free" narrative.
#[allow(clippy::too_many_lines)]
pub async fn export(scoped: &ScopedStore<'_>) -> Result<Snapshot, StoreError> {
    let mut clients = Vec::new();
    for record in scoped.clients().list().await? {
        // The auth record carries the non-secret key material and the secret
        // PRESENCE (never the hash itself, which stays in `secret_hash` and is
        // read only to decide whether a reference is emitted).
        let auth = scoped.clients().auth_record(&record.id).await?;
        let mut redirect_uris = record.redirect_uris;
        redirect_uris.sort();
        let mut post_logout_redirect_uris = record.post_logout_redirect_uris;
        post_logout_redirect_uris.sort();
        clients.push(ClientSnapshot {
            client_id: record.id.to_string(),
            display_name: record.display_name,
            token_endpoint_auth_method: record.auth_method,
            redirect_uris,
            post_logout_redirect_uris,
            frontchannel_logout_uri: record.frontchannel_logout_uri,
            frontchannel_logout_session_required: record.frontchannel_logout_session_required,
            consent_mode: record.consent_mode,
            skip_consent: record.skip_consent,
            store_skipped_consent: record.store_skipped_consent,
            require_pushed_authorization_requests: record.require_pushed_authorization_requests,
            require_auth_time: record.require_auth_time,
            jwks: project_jwks_public(auth.jwks),
            jwks_uri: auth.jwks_uri,
            token_endpoint_auth_signing_alg: auth.token_endpoint_auth_signing_alg,
            refresh_rotation: auth.refresh_rotation,
            secret: auth.secret_hash.map(|_| SecretRef {
                reference: CLIENT_SECRET_REFERENCE.to_string(),
            }),
        });
    }
    // Order by the stable public natural key so the array is canonical
    // independent of insertion time.
    clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));

    let mut resource_server: Vec<ResourceServerSnapshot> = scoped
        .resource_servers()
        .list()
        .await?
        .into_iter()
        .map(|record| ResourceServerSnapshot {
            audience: record.audience,
            token_format: record.token_format.as_str().to_string(),
            access_token_ttl_secs: record.access_token_ttl_secs,
        })
        .collect();
    // Re-sort by the stable public natural key in Rust (byte / code-point order),
    // exactly as the clients are sorted above. The SQL `ORDER BY audience` is
    // collation-dependent, so relying on it would make the byte order vary across
    // differently-collated Postgres deployments and break diffability; a Rust
    // `str::cmp` is collation-independent and reproducible.
    resource_server.sort_by(|a, b| a.audience.cmp(&b.audience));

    let mut dcr_policy = Vec::new();
    for record in scoped.dcr_policies().list_all().await? {
        // Embed the primitive list as parsed JSON so it canonicalizes recursively.
        // A stored policy is validated JSON on write; a decode fault here is a real
        // persistence corruption, surfaced rather than swallowed.
        let primitives: serde_json::Value =
            serde_json::from_str(&record.primitives).map_err(serde_fault)?;
        dcr_policy.push(DcrPolicySnapshot {
            name: record.name,
            primitives,
        });
    }
    // Re-sort by the stable natural key in Rust for the same collation-independence
    // reason as the resource servers above: the SQL `ORDER BY name` is
    // collation-dependent and must not decide the canonical byte order.
    dcr_policy.sort_by(|a, b| a.name.cmp(&b.name));

    // Environment variables (issue #45): non-secret promotable config, carried
    // name AND value. Secrets are NEVER read here (their value never travels; only
    // a reference does), so the export stays secret-free by construction.
    let mut variable: Vec<VariableSnapshot> = scoped
        .environment_variables()
        .list_all()
        .await?
        .into_iter()
        .map(|record| VariableSnapshot {
            name: record.name,
            value: record.value,
        })
        .collect();
    // Re-sort by the stable natural key in Rust (collation-independent), exactly as
    // the resource servers and policies above.
    variable.sort_by(|a, b| a.name.cmp(&b.name));

    // Federation connectors (issue #75): the connector DEFINITION is promotable
    // config a snapshot carries; the upstream client SECRET is NEVER read here (its
    // value is sealed per environment and never travels), so the export carries only
    // a NAMED REFERENCE to it and stays secret-free by construction. The stored
    // `definition_json` is already the secret-free projection (the client_secret
    // field was stripped before it was ever persisted).
    let mut connector = Vec::new();
    for record in scoped.connectors().list_all().await? {
        let definition: serde_json::Value =
            serde_json::from_str(&record.definition_json).map_err(serde_fault)?;
        connector.push(ConnectorSnapshot {
            connector_slug: record.slug,
            definition,
            enabled: record.enabled,
            // Every connector carries an upstream client secret, exported as a named
            // REFERENCE, never the value (the #58 proof).
            secret: Some(SecretRef {
                reference: CONNECTOR_CLIENT_SECRET_REFERENCE.to_string(),
            }),
        });
    }
    // Re-sort by the stable natural key in Rust for the same collation-independence
    // reason as the resources above.
    connector.sort_by(|a, b| a.connector_slug.cmp(&b.connector_slug));

    // Organization-to-connector bindings (issue #77): secret-free per-environment
    // config. Ordered by the stable (organization_id, connector_id) natural key.
    let mut org_connection: Vec<OrgConnectionSnapshot> = scoped
        .org_connections()
        .list_all()
        .await?
        .into_iter()
        .map(|record| OrgConnectionSnapshot {
            organization_id: record.organization_id,
            connector_id: record.connector_id,
            overlay_min_acr: record.overlay_min_acr,
            max_age_secs: record.max_age_secs,
            overlay_min_class: record.overlay_min_class,
            capture_upstream_tokens: record.capture_upstream_tokens,
            enabled: record.enabled,
        })
        .collect();
    org_connection.sort_by(|a, b| {
        (a.organization_id.as_str(), a.connector_id.as_str())
            .cmp(&(b.organization_id.as_str(), b.connector_id.as_str()))
    });

    // Routing rules (issue #77): the user selector travels as an OPAQUE base64 blind
    // index, never a plaintext identifier, so the export stays free of user PII.
    // Ordered by the stable (rule_kind, selector, org_connection_id) natural key.
    let mut routing_rule: Vec<RoutingRuleSnapshot> = scoped
        .routing_rules()
        .list_all()
        .await?
        .into_iter()
        .map(|record| RoutingRuleSnapshot {
            rule_kind: record.rule_kind,
            domain: record.domain_norm,
            client_id: record.client_id,
            user_bidx: record.user_bidx.map(|bytes| URL_SAFE_NO_PAD.encode(bytes)),
            org_connection_id: record.org_connection_id,
            priority: i64::from(record.priority),
            enabled: record.enabled,
        })
        .collect();
    routing_rule.sort_by(|a, b| routing_rule_order_key(a).cmp(&routing_rule_order_key(b)));

    // Upstream-token retrieval grants (issue #77, PR 3): secret-free per-environment
    // authorization config. The captured tokens themselves are Runtime and never read
    // here, so the export stays free of token material by construction. Ordered by the
    // stable (client_id, org_connection_id) natural key.
    let mut upstream_token_grant: Vec<UpstreamTokenGrantSnapshot> = scoped
        .upstream_token_grants()
        .list_all()
        .await?
        .into_iter()
        .map(|record| UpstreamTokenGrantSnapshot {
            client_id: record.client_id,
            org_connection_id: record.org_connection_id,
            enabled: record.enabled,
        })
        .collect();
    upstream_token_grant.sort_by(|a, b| {
        (a.client_id.as_str(), a.org_connection_id.as_str())
            .cmp(&(b.client_id.as_str(), b.org_connection_id.as_str()))
    });

    // Per-environment brands (issue #86): non-secret promotable branding config. The
    // TYPED tokens and the sanitized slots are embedded as PARSED JSON so they
    // canonicalize recursively (a decode fault here is a real persistence corruption,
    // surfaced rather than swallowed). No secret and no PII travels. Ordered by the
    // stable slug natural key.
    let mut brand = Vec::new();
    for record in scoped.brands().list_all().await? {
        let tokens: serde_json::Value =
            serde_json::from_str(&record.tokens_json).map_err(serde_fault)?;
        let tokens_dark = match record.tokens_dark_json {
            Some(json) => Some(serde_json::from_str(&json).map_err(serde_fault)?),
            None => None,
        };
        let slots: serde_json::Value =
            serde_json::from_str(&record.slots_json).map_err(serde_fault)?;
        brand.push(BrandSnapshot {
            slug: record.slug,
            is_default: record.is_default,
            product_name: record.product_name,
            show_wordmark: record.show_wordmark,
            brand_token: record.brand_token,
            tokens,
            tokens_dark,
            slots,
        });
    }
    brand.sort_by(|a, b| a.slug.cmp(&b.slug));

    // Per-environment locale bundles (issue #86, PR 2): non-secret promotable localization
    // config. The entries map is embedded as PARSED JSON so it canonicalizes recursively (a
    // decode fault here is a real persistence corruption, surfaced rather than swallowed). No
    // secret and no PII travels. Ordered by the stable locale-tag natural key.
    let mut locale_bundle = Vec::new();
    for record in scoped.locale_bundles().list_all().await? {
        let entries: serde_json::Value =
            serde_json::from_str(&record.entries_json).map_err(serde_fault)?;
        locale_bundle.push(LocaleBundleSnapshot {
            locale: record.locale,
            is_env_default: record.is_env_default,
            entries,
        });
    }
    locale_bundle.sort_by(|a, b| a.locale.cmp(&b.locale));

    Ok(Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
        resources: SnapshotResources {
            client: clients,
            resource_server,
            dcr_policy,
            variable,
            connector,
            org_connection,
            routing_rule,
            upstream_token_grant,
            brand,
            locale_bundle,
        },
    })
}

/// The stable natural-key tuple a routing-rule snapshot array is ordered by (issue
/// #77): the kind, then the present selector, then the target org connection. Every
/// component is a `&str`, so the comparison is collation-independent and reproducible.
fn routing_rule_order_key(rule: &RoutingRuleSnapshot) -> (&str, &str, &str) {
    let selector = rule
        .domain
        .as_deref()
        .or(rule.client_id.as_deref())
        .or(rule.user_bidx.as_deref())
        .unwrap_or("");
    (
        rule.rule_kind.as_str(),
        selector,
        rule.org_connection_id.as_str(),
    )
}

/// Project a stored client JWK Set to its PUBLIC members only, making the export
/// SECRET-FREE BY CONSTRUCTION (issue #43).
///
/// The `jwks` column is trusted-key input the client registered; `jose`'s
/// `trusted_key_from_jwk` reads only the public members and IGNORES private
/// parameters, so a JWK carrying private key material (RSA `d`/`p`/`q`/`dp`/`dq`/
/// `qi`, EC/OKP `d`, symmetric `k`) can be accepted and persisted verbatim. Copying
/// that column into a snapshot would leak a private signing key into a document that
/// is meant to be safe to commit, and [`validate_document`] would then reject the
/// very bytes the export produced. This projection removes exactly the parameters
/// [`PRIVATE_JWK_PARAMS`] names (the ONE shared definition of "private" the
/// validator's [`scan_private_params`] also uses), so export and import agree and an
/// exported snapshot round-trips clean. A symmetric (`kty: "oct"`) JWK is dropped
/// entirely: it is all-secret, with no public half worth carrying. The surviving
/// public members (`kty`, `kid`, `use`, `alg`, `n`, `e`, `x`, `y`, `crv`) are kept.
///
/// Returns `None` when the stored value is absent or does not parse as JSON: there
/// is no public key material to project, so none is emitted.
fn project_jwks_public(jwks: Option<String>) -> Option<String> {
    let text = jwks?;
    let mut value: serde_json::Value = serde_json::from_str(&text).ok()?;
    // Drop symmetric keys outright (all-secret), then strip every private parameter
    // from what remains.
    if let Some(keys) = value
        .get_mut("keys")
        .and_then(serde_json::Value::as_array_mut)
    {
        keys.retain(|key| key.get("kty").and_then(serde_json::Value::as_str) != Some("oct"));
    }
    strip_private_params(&mut value);
    serde_json::to_string(&value).ok()
}

/// Recursively remove every [`PRIVATE_JWK_PARAMS`] member from `value`, mirroring
/// the traversal [`scan_private_params`] uses to DETECT them, so a projected JWK Set
/// carries no parameter the validator would reject. Export (strip) and import
/// (reject) therefore share one definition of "private".
fn strip_private_params(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for param in PRIVATE_JWK_PARAMS {
                map.remove(param);
            }
            for child in map.values_mut() {
                strip_private_params(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                strip_private_params(item);
            }
        }
        _ => {}
    }
}

/// One validation failure against the snapshot format, carrying a JSON Pointer
/// path to the offending location and a human-readable message (issue #43).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotViolation {
    /// An RFC 6901 JSON Pointer to the offending location (for example
    /// `/resources/client/0/token_endpoint_auth_method`, or the empty string for
    /// a document-level fault).
    pub path: String,
    /// A human-readable description of the violation.
    pub message: String,
}

impl SnapshotViolation {
    /// Build a violation at `path` with `message`.
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// The recognized `token_endpoint_auth_method` values a snapshot client may carry.
const CLIENT_AUTH_METHODS: [&str; 5] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "client_secret_jwt",
    "none",
];

/// The recognized `token_format` values a snapshot resource server may carry.
const RESOURCE_SERVER_FORMATS: [&str; 2] = ["at_jwt", "opaque"];

/// Every key a snapshot `client` element may carry (the published schema pins
/// `additionalProperties: false`, so any other key is rejected).
const CLIENT_KEYS: [&str; 16] = [
    "client_id",
    "display_name",
    "token_endpoint_auth_method",
    "redirect_uris",
    "post_logout_redirect_uris",
    "frontchannel_logout_uri",
    "frontchannel_logout_session_required",
    "consent_mode",
    "skip_consent",
    "store_skipped_consent",
    "require_pushed_authorization_requests",
    "require_auth_time",
    "jwks",
    "jwks_uri",
    "token_endpoint_auth_signing_alg",
    "refresh_rotation",
];

/// The one additional key a `client` element may carry: the secret REFERENCE slot.
const CLIENT_SECRET_KEY: &str = "secret";

/// Every key a snapshot `resource_server` element may carry.
const RESOURCE_SERVER_KEYS: [&str; 3] = ["audience", "token_format", "access_token_ttl_secs"];

/// Every key a snapshot `dcr_policy` element may carry.
const DCR_POLICY_KEYS: [&str; 2] = ["name", "primitives"];

/// Every key a snapshot `variable` element may carry (issue #45).
const VARIABLE_KEYS: [&str; 2] = ["name", "value"];

/// Every key a snapshot `brand` element may carry (issue #86). No secret slot: a brand
/// holds no secret material. The published schema pins `additionalProperties: false`.
const BRAND_KEYS: [&str; 8] = [
    "slug",
    "is_default",
    "product_name",
    "show_wordmark",
    "brand_token",
    "tokens",
    "tokens_dark",
    "slots",
];

/// Every key a snapshot `locale_bundle` element may carry (issue #86, PR 2). No secret slot: a
/// locale bundle holds no secret material. The published schema pins `additionalProperties:
/// false`.
const LOCALE_BUNDLE_KEYS: [&str; 3] = ["locale", "is_env_default", "entries"];

/// Every key a snapshot `connector` element may carry, besides the secret REFERENCE
/// slot (issue #75). The published schema pins `additionalProperties: false`.
const CONNECTOR_KEYS: [&str; 3] = ["connector_slug", "definition", "enabled"];

/// Every key a snapshot `org_connection` element may carry (issue #77). No secret
/// slot: a binding holds no secret material.
const ORG_CONNECTION_KEYS: [&str; 7] = [
    "organization_id",
    "connector_id",
    "overlay_min_acr",
    "max_age_secs",
    "overlay_min_class",
    "capture_upstream_tokens",
    "enabled",
];

/// Every key a snapshot `routing_rule` element may carry (issue #77). The user
/// selector is an opaque blind index, never a plaintext identifier.
const ROUTING_RULE_KEYS: [&str; 7] = [
    "rule_kind",
    "domain",
    "client_id",
    "user_bidx",
    "org_connection_id",
    "priority",
    "enabled",
];

/// The recognized `rule_kind` values a snapshot routing rule may carry (issue #77).
const ROUTING_RULE_KINDS: [&str; 3] = ["domain", "app", "user"];

/// Every key a snapshot `upstream_token_grant` element may carry (issue #77, PR 3). It
/// is secret-free: only the client and org-connection references and the enabled flag.
const UPSTREAM_TOKEN_GRANT_KEYS: [&str; 3] = ["client_id", "org_connection_id", "enabled"];

/// Object keys that would carry RAW secret material and must never appear in a
/// snapshot: the presence of any is a hard rejection (issue #43, "an import
/// document containing raw secret-shaped material in a secret-typed field is
/// rejected"). A secret is referenced by name ([`SecretRef`]), never inlined.
///
/// Note the `secret` key itself is NOT here: it is the legitimate secret-REFERENCE
/// field, validated separately by [`validate_secret_field`] to be a
/// `{"reference": ...}` object and never a raw inline value.
const FORBIDDEN_SECRET_KEYS: [&str; 5] = [
    "client_secret",
    "secret_hash",
    "password",
    "private_key",
    "registration_access_token",
];

/// The private JWK parameters that must never appear in a snapshot: a `jwks`
/// carrying any of these holds a PRIVATE key, not a public verification key
/// (issue #43). Covers the RSA/EC private components and the symmetric key.
// Every RFC 7518 private JWK parameter. `oth` is the multi-prime RSA array of
// additional {r, d, t} factors (RFC 7518 6.3.2.7): `r` is a prime factor of the
// modulus and is as secret as `p`/`q`, so the whole `oth` array is stripped on
// export and rejected on import (the array's nested `d`/`t` go with it).
const PRIVATE_JWK_PARAMS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// Validate a snapshot document against the published format, enumerating EVERY
/// violation with its JSON Pointer path, WITHOUT applying anything (issue #43).
///
/// This is the "validated import" surface: an importer runs this over the full
/// document before touching any state, so an invalid document changes nothing and
/// the caller learns all violations at once, not just the first. Applying a valid
/// snapshot into an environment (resolving secret references against the target
/// secret store, issue #45, and the transactional diff/plan/apply, issue #44) is
/// the promotion engine's job and is deliberately not done here.
///
/// Enforced (fail closed):
///
/// - the document is valid JSON with the expected top-level shape;
/// - `schema_version` equals [`SNAPSHOT_SCHEMA_VERSION`];
/// - `resources` carries only known promotable resource-type keys;
/// - every element carries its required fields with the right types and enum
///   values; and
/// - NO raw secret-shaped material appears anywhere in the document (neither a
///   forbidden key nor a private JWK parameter), the SECRET-FREE invariant.
///
/// # Errors
///
/// The `Vec<SnapshotViolation>` of every violation found (never empty on the error
/// path). On success the parsed, valid [`Snapshot`].
pub fn validate_document(bytes: &[u8]) -> Result<Snapshot, Vec<SnapshotViolation>> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            return Err(vec![SnapshotViolation::new(
                "",
                format!("document is not valid JSON: {error}"),
            )]);
        }
    };
    let mut violations = Vec::new();
    validate_value(&value, &mut violations);
    if !violations.is_empty() {
        return Err(violations);
    }
    // Structural validation passed, so the typed deserialize cannot fail; if it
    // somehow does, surface it as a document-level violation rather than panic.
    serde_json::from_value(value).map_err(|error| {
        vec![SnapshotViolation::new(
            "",
            format!("document did not deserialize after validation: {error}"),
        )]
    })
}

/// Validate the top-level document `value`, pushing any violations.
fn validate_value(value: &serde_json::Value, violations: &mut Vec<SnapshotViolation>) {
    let Some(object) = value.as_object() else {
        violations.push(SnapshotViolation::new("", "document must be a JSON object"));
        return;
    };

    match object
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
    {
        Some(version) if version == SNAPSHOT_SCHEMA_VERSION => {}
        Some(other) => violations.push(SnapshotViolation::new(
            "/schema_version",
            format!("unsupported schema version {other:?}; expected {SNAPSHOT_SCHEMA_VERSION:?}"),
        )),
        None => violations.push(SnapshotViolation::new(
            "/schema_version",
            "missing required string field",
        )),
    }

    let Some(resources) = object.get("resources") else {
        violations.push(SnapshotViolation::new(
            "/resources",
            "missing required object field",
        ));
        return;
    };
    let Some(resources) = resources.as_object() else {
        violations.push(SnapshotViolation::new(
            "/resources",
            "must be a JSON object",
        ));
        return;
    };

    // Only known promotable resource-type keys may appear.
    let known: Vec<&str> = SNAPSHOT_RESOURCE_TYPES.iter().map(|t| t.as_str()).collect();
    for key in resources.keys() {
        if !known.contains(&key.as_str()) {
            violations.push(SnapshotViolation::new(
                format!("/resources/{key}"),
                format!("unknown resource type {key:?}; only promotable types may appear"),
            ));
        }
    }

    for resource_type in SNAPSHOT_RESOURCE_TYPES {
        let key = resource_type.as_str();
        let Some(array) = resources.get(key) else {
            continue;
        };
        let path = format!("/resources/{key}");
        let Some(items) = array.as_array() else {
            violations.push(SnapshotViolation::new(path, "must be a JSON array"));
            continue;
        };
        for (index, item) in items.iter().enumerate() {
            let item_path = format!("{path}/{index}");
            validate_resource(resource_type, item, &item_path, violations);
        }
    }
}

/// Validate a single resource element of `resource_type` at `path`.
// One flat per-resource-type match (one arm per promotable type); splitting it would
// scatter the field-by-field validation the reviewer reads in one place.
#[allow(clippy::too_many_lines)]
fn validate_resource(
    resource_type: ResourceType,
    item: &serde_json::Value,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    let Some(object) = item.as_object() else {
        violations.push(SnapshotViolation::new(path, "must be a JSON object"));
        return;
    };

    // The SECRET-FREE invariant applies to every resource: no forbidden secret key
    // anywhere in the element, and no private JWK parameter in an embedded key set.
    reject_secret_material(object, path, violations);

    match resource_type {
        ResourceType::Client => {
            reject_unknown_keys(
                object,
                &CLIENT_KEYS,
                Some(CLIENT_SECRET_KEY),
                path,
                violations,
            );
            require_nonempty_string(object, "client_id", path, violations);
            require_nonempty_string(object, "display_name", path, violations);
            require_enum(
                object,
                "token_endpoint_auth_method",
                &CLIENT_AUTH_METHODS,
                path,
                violations,
            );
            validate_secret_field(object, path, violations);
        }
        ResourceType::ResourceServer => {
            reject_unknown_keys(object, &RESOURCE_SERVER_KEYS, None, path, violations);
            require_nonempty_string(object, "audience", path, violations);
            require_enum(
                object,
                "token_format",
                &RESOURCE_SERVER_FORMATS,
                path,
                violations,
            );
        }
        ResourceType::DcrPolicy => {
            reject_unknown_keys(object, &DCR_POLICY_KEYS, None, path, violations);
            require_nonempty_string(object, "name", path, violations);
            match object.get("primitives") {
                Some(serde_json::Value::Array(_)) => {}
                Some(_) => violations.push(SnapshotViolation::new(
                    format!("{path}/primitives"),
                    "must be a JSON array",
                )),
                None => violations.push(SnapshotViolation::new(
                    format!("{path}/primitives"),
                    "missing required array field",
                )),
            }
        }
        ResourceType::Variable => {
            // A variable is a non-secret name -> value pair (issue #45). The value
            // is a plain string; the forbidden-secret-key scan above already
            // guarantees no secret-shaped material rides along under a novel key.
            reject_unknown_keys(object, &VARIABLE_KEYS, None, path, violations);
            require_nonempty_string(object, "name", path, violations);
            match object.get("value") {
                Some(serde_json::Value::String(_)) => {}
                Some(_) => violations.push(SnapshotViolation::new(
                    format!("{path}/value"),
                    "must be a JSON string",
                )),
                None => violations.push(SnapshotViolation::new(
                    format!("{path}/value"),
                    "missing required string field",
                )),
            }
        }
        ResourceType::Connector => {
            reject_unknown_keys(
                object,
                &CONNECTOR_KEYS,
                Some(CLIENT_SECRET_KEY),
                path,
                violations,
            );
            require_nonempty_string(object, "connector_slug", path, violations);
            match object.get("definition") {
                Some(serde_json::Value::Object(_)) => {}
                Some(_) => violations.push(SnapshotViolation::new(
                    format!("{path}/definition"),
                    "must be a JSON object",
                )),
                None => violations.push(SnapshotViolation::new(
                    format!("{path}/definition"),
                    "missing required object field",
                )),
            }
            // The upstream client secret is a REFERENCE, never inline (the #75 / #58
            // proof), validated exactly like a client's secret slot.
            validate_secret_field(object, path, violations);
        }
        ResourceType::OrgConnection => {
            reject_unknown_keys(object, &ORG_CONNECTION_KEYS, None, path, violations);
            require_nonempty_string(object, "organization_id", path, violations);
            require_nonempty_string(object, "connector_id", path, violations);
        }
        ResourceType::RoutingRule => {
            reject_unknown_keys(object, &ROUTING_RULE_KEYS, None, path, violations);
            require_enum(object, "rule_kind", &ROUTING_RULE_KINDS, path, violations);
            require_nonempty_string(object, "org_connection_id", path, violations);
        }
        ResourceType::UpstreamTokenGrant => {
            reject_unknown_keys(object, &UPSTREAM_TOKEN_GRANT_KEYS, None, path, violations);
            require_nonempty_string(object, "client_id", path, violations);
            require_nonempty_string(object, "org_connection_id", path, violations);
        }
        ResourceType::Brand => {
            // A brand is secret-free branding config (issue #86): a slug, plain wordmark
            // fields, and the TYPED tokens / sanitized slots as JSON objects. The
            // forbidden-secret-key scan above already blocks secret-shaped material.
            reject_unknown_keys(object, &BRAND_KEYS, None, path, violations);
            require_nonempty_string(object, "slug", path, violations);
            require_nonempty_string(object, "product_name", path, violations);
            for field in ["tokens", "slots"] {
                match object.get(field) {
                    Some(serde_json::Value::Object(_)) => {}
                    Some(_) => violations.push(SnapshotViolation::new(
                        format!("{path}/{field}"),
                        "must be a JSON object",
                    )),
                    None => violations.push(SnapshotViolation::new(
                        format!("{path}/{field}"),
                        "missing required object field",
                    )),
                }
            }
        }
        ResourceType::LocaleBundle => {
            // A locale bundle is secret-free localization config (issue #86, PR 2): a BCP47
            // tag and the entries map (numeric message id string to plain text) as a JSON
            // object. The forbidden-secret-key scan above already blocks secret-shaped
            // material; a bundle string is plain text, escaped on render, never markup.
            reject_unknown_keys(object, &LOCALE_BUNDLE_KEYS, None, path, violations);
            require_nonempty_string(object, "locale", path, violations);
            match object.get("entries") {
                Some(serde_json::Value::Object(_)) => {}
                Some(_) => violations.push(SnapshotViolation::new(
                    format!("{path}/entries"),
                    "must be a JSON object",
                )),
                None => violations.push(SnapshotViolation::new(
                    format!("{path}/entries"),
                    "missing required object field",
                )),
            }
        }
        // Only the promotable set is ever passed here (the caller iterates
        // SNAPSHOT_RESOURCE_TYPES); a non-promotable type is a programmer error, not
        // a document fault, so it is reported at the element path.
        _ => violations.push(SnapshotViolation::new(
            path,
            "resource type is not promotable and cannot appear in a snapshot",
        )),
    }
}

/// Reject any key on `object` not in `allowed` (plus the optional `extra` key):
/// the published schema pins `additionalProperties: false` on every resource, so
/// an unexpected field is caught rather than silently dropped, which also blocks
/// smuggling secret-shaped material under a novel key name.
fn reject_unknown_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    extra: Option<&str>,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    for key in object.keys() {
        let permitted = allowed.contains(&key.as_str()) || extra == Some(key.as_str());
        if !permitted {
            violations.push(SnapshotViolation::new(
                format!("{path}/{key}"),
                format!("unknown field {key:?}; the snapshot schema permits no additional fields"),
            ));
        }
    }
}

/// Reject raw secret-shaped material anywhere in `object` (issue #43): a forbidden
/// top-level or nested key, or a private JWK parameter inside an embedded `jwks`.
fn reject_secret_material(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    scan_forbidden_keys(&serde_json::Value::Object(object.clone()), path, violations);
    if let Some(jwks) = object.get("jwks") {
        reject_private_jwk(jwks, &format!("{path}/jwks"), violations);
    }
}

/// Recursively flag any [`FORBIDDEN_SECRET_KEYS`] key found under `value`.
fn scan_forbidden_keys(
    value: &serde_json::Value,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}/{key}");
                if FORBIDDEN_SECRET_KEYS.contains(&key.as_str()) {
                    violations.push(SnapshotViolation::new(
                        child_path.clone(),
                        format!(
                            "raw secret material in secret-typed field {key:?}; a secret must be a \
                             named reference, never an inline value"
                        ),
                    ));
                }
                scan_forbidden_keys(child, &child_path, violations);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_forbidden_keys(item, &format!("{path}/{index}"), violations);
            }
        }
        _ => {}
    }
}

/// Reject a private-key JWK inside an embedded JWK Set: a `jwks` string that
/// parses to a JWK carrying any private parameter (`d`, `p`, `q`, `dp`, `dq`,
/// `qi`, or a symmetric `k`) is secret material, not a public verification key.
fn reject_private_jwk(
    jwks: &serde_json::Value,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    let Some(text) = jwks.as_str() else {
        // A non-string jwks is a shape fault the client validator does not require,
        // but a present-and-wrong-typed jwks is worth flagging.
        violations.push(SnapshotViolation::new(path, "jwks must be a JSON string"));
        return;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) else {
        violations.push(SnapshotViolation::new(path, "jwks is not valid JSON"));
        return;
    };
    scan_private_params(&parsed, path, &PRIVATE_JWK_PARAMS, violations);
}

/// Recursively flag any private JWK parameter under `value`.
fn scan_private_params(
    value: &serde_json::Value,
    path: &str,
    params: &[&str],
    violations: &mut Vec<SnapshotViolation>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for param in params {
                if map.contains_key(*param) {
                    violations.push(SnapshotViolation::new(
                        format!("{path}/{param}"),
                        format!(
                            "private JWK parameter {param:?} in a snapshot; only public \
                             verification keys may appear"
                        ),
                    ));
                }
            }
            for (key, child) in map {
                scan_private_params(child, &format!("{path}/{key}"), params, violations);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_private_params(item, &format!("{path}/{index}"), params, violations);
            }
        }
        _ => {}
    }
}

/// Validate a client's `secret` field (issue #43): it is the secret-REFERENCE
/// slot, so it must be absent or an object `{"reference": <non-empty string>}`. A
/// raw string (or any non-object) in it is inline secret material and is rejected,
/// which is the "raw secret-shaped material in a secret-typed field" rule.
fn validate_secret_field(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    let Some(secret) = object.get("secret") else {
        return;
    };
    let field_path = format!("{path}/secret");
    let Some(reference_object) = secret.as_object() else {
        violations.push(SnapshotViolation::new(
            field_path,
            "raw secret material in secret-typed field \"secret\"; a secret must be a named \
             reference object {\"reference\": ...}, never an inline value",
        ));
        return;
    };
    match reference_object
        .get("reference")
        .and_then(serde_json::Value::as_str)
    {
        Some(reference) if !reference.is_empty() => {}
        _ => violations.push(SnapshotViolation::new(
            format!("{field_path}/reference"),
            "a secret reference must carry a non-empty \"reference\" string",
        )),
    }
}

/// Require a non-empty string field `field` on `object`, else push a violation.
fn require_nonempty_string(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    match object.get(field).and_then(serde_json::Value::as_str) {
        Some(value) if !value.is_empty() => {}
        Some(_) => violations.push(SnapshotViolation::new(
            format!("{path}/{field}"),
            "must be a non-empty string",
        )),
        None => violations.push(SnapshotViolation::new(
            format!("{path}/{field}"),
            "missing required string field",
        )),
    }
}

/// Require a string field `field` whose value is one of `allowed`.
fn require_enum(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    allowed: &[&str],
    path: &str,
    violations: &mut Vec<SnapshotViolation>,
) {
    match object.get(field).and_then(serde_json::Value::as_str) {
        Some(value) if allowed.contains(&value) => {}
        Some(other) => violations.push(SnapshotViolation::new(
            format!("{path}/{field}"),
            format!("value {other:?} is not one of {allowed:?}"),
        )),
        None => violations.push(SnapshotViolation::new(
            format!("{path}/{field}"),
            "missing required string field",
        )),
    }
}

/// The classification-driven coverage check, callable from tests and CI (issue
/// #43): [`SNAPSHOT_RESOURCE_TYPES`] MUST equal exactly the set [`classify`] marks
/// [`ResourceClassification::Promotable`]. Returns the promotable types that are
/// NOT covered by the snapshot (a coverage gap) paired with the snapshot types
/// that are NOT promotable (an over-reach); both empty means the binding holds.
#[must_use]
pub fn classification_coverage_gaps() -> (Vec<ResourceType>, Vec<ResourceType>) {
    let promotable: Vec<ResourceType> = ResourceType::ALL
        .into_iter()
        .filter(|t| classify(*t) == ResourceClassification::Promotable)
        .collect();
    let missing: Vec<ResourceType> = promotable
        .iter()
        .copied()
        .filter(|t| !SNAPSHOT_RESOURCE_TYPES.contains(t))
        .collect();
    let overreach: Vec<ResourceType> = SNAPSHOT_RESOURCE_TYPES
        .into_iter()
        .filter(|t| classify(*t) != ResourceClassification::Promotable)
        .collect();
    (missing, overreach)
}

#[cfg(test)]
mod tests {
    use super::{
        PRIVATE_JWK_PARAMS, SNAPSHOT_RESOURCE_TYPES, SNAPSHOT_SCHEMA_VERSION, Snapshot,
        SnapshotResources, classification_coverage_gaps, project_jwks_public, validate_document,
    };
    use crate::classification::{ResourceClassification, ResourceType, classify};

    fn empty_snapshot() -> Snapshot {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            resources: SnapshotResources::default(),
        }
    }

    #[test]
    fn snapshot_types_are_exactly_the_promotable_set() {
        // The live binding: the snapshot's resource-type set is exactly the
        // classification's promotable set. This is the CI coverage check the
        // acceptance criteria require (a promotable type missing from the export,
        // or a non-promotable type present, fails here).
        let (missing, overreach) = classification_coverage_gaps();
        assert!(
            missing.is_empty(),
            "promotable resource types missing from the snapshot: {missing:?}"
        );
        assert!(
            overreach.is_empty(),
            "non-promotable resource types present in the snapshot: {overreach:?}"
        );
    }

    #[test]
    fn every_environment_identity_and_runtime_type_is_excluded() {
        // The complement of the coverage check: no environment-identity or runtime
        // type may appear in SNAPSHOT_RESOURCE_TYPES.
        for resource in ResourceType::ALL {
            if classify(resource) != ResourceClassification::Promotable {
                assert!(
                    !SNAPSHOT_RESOURCE_TYPES.contains(&resource),
                    "{} is {} and must be excluded from snapshots",
                    resource.as_str(),
                    classify(resource).as_str()
                );
            }
        }
    }

    #[test]
    fn canonical_form_sorts_keys_and_is_whitespace_free() {
        let bytes = empty_snapshot().to_canonical_bytes().expect("canonicalize");
        let text = String::from_utf8(bytes).expect("utf8");
        // Keys sorted: resources before schema_version, and within resources the
        // resource-type keys are sorted (client, dcr_policy, resource_server,
        // variable) regardless of struct field order.
        assert_eq!(
            text,
            "{\"resources\":{\"brand\":[],\"client\":[],\"connector\":[],\"dcr_policy\":[],\
             \"locale_bundle\":[],\"org_connection\":[],\"resource_server\":[],\
             \"routing_rule\":[],\"upstream_token_grant\":[],\"variable\":[]},\
             \"schema_version\":\"ironauth.config-snapshot/v1\"}"
        );
    }

    #[test]
    fn canonical_serialization_is_deterministic_and_round_trips() {
        let a = empty_snapshot().to_canonical_string().expect("a");
        let b = empty_snapshot().to_canonical_string().expect("b");
        assert_eq!(a, b, "two canonical serializations must be byte-identical");
        // Parse the canonical bytes back and re-serialize: still byte-identical.
        let parsed = validate_document(a.as_bytes()).expect("valid");
        let reserialized = parsed.to_canonical_string().expect("reserialize");
        assert_eq!(a, reserialized, "canonical form must round-trip losslessly");
    }

    #[test]
    fn validate_rejects_unknown_schema_version() {
        let doc = r#"{"schema_version":"nope/v9","resources":{}}"#;
        let violations = validate_document(doc.as_bytes()).expect_err("rejected");
        assert!(violations.iter().any(|v| v.path == "/schema_version"));
    }

    #[test]
    fn validate_rejects_raw_secret_material_with_path() {
        let doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"client_secret_basic","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"client_secret":"super-secret-value"}}]}}}}"#
        );
        let violations = validate_document(doc.as_bytes()).expect_err("rejected");
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/client/0/client_secret"),
            "raw secret material must be rejected with its path: {violations:?}"
        );
    }

    #[test]
    fn validate_accepts_a_secret_reference_but_rejects_a_raw_secret_string() {
        // A `secret` REFERENCE object is legitimate (the named indirection).
        let ok = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"client_secret_basic","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"secret":{{"reference":"client_secret"}}}}]}}}}"#
        );
        validate_document(ok.as_bytes()).expect("a secret reference is valid");

        // A raw STRING in the `secret` field is inline material and is rejected.
        let bad = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"client_secret_basic","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"secret":"raw-secret-value"}}]}}}}"#
        );
        let violations = validate_document(bad.as_bytes()).expect_err("raw secret rejected");
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/client/0/secret"),
            "a raw secret string must be rejected with its path: {violations:?}"
        );
    }

    #[test]
    fn validate_accepts_a_connector_secret_reference_but_rejects_a_raw_secret() {
        // A connector's upstream client secret is a REFERENCE, never inline (the #75
        // / #58 proof). A reference object validates; a raw string is rejected.
        let definition = r#"{"connector_id":"acme","display_name":"Acme","protocol":"oidc","endpoints":{"issuer":"https://acme.example.com"},"scopes":["openid"],"client_id":"ic"}"#;
        let ok = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"connector":[{{"connector_slug":"acme","definition":{definition},"enabled":true,"secret":{{"reference":"connector_client_secret"}}}}]}}}}"#
        );
        validate_document(ok.as_bytes()).expect("a connector secret reference is valid");

        let bad = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"connector":[{{"connector_slug":"acme","definition":{definition},"enabled":true,"secret":"raw-upstream-secret"}}]}}}}"#
        );
        let violations = validate_document(bad.as_bytes()).expect_err("raw secret rejected");
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/connector/0/secret"),
            "a raw connector secret must be rejected with its path: {violations:?}"
        );
    }

    #[test]
    fn validate_rejects_private_jwk_material() {
        let jwks = r#"{"keys":[{"kty":"RSA","n":"abc","e":"AQAB","d":"PRIVATE"}]}"#;
        let doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"private_key_jwt","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"jwks":{jwks:?}}}]}}}}"#
        );
        let violations = validate_document(doc.as_bytes()).expect_err("rejected");
        assert!(
            violations.iter().any(|v| v.path.ends_with("/d")),
            "a private JWK parameter must be rejected: {violations:?}"
        );

        // A multi-prime RSA `oth` array carries prime factors and CRT coefficients
        // (RFC 7518 6.3.2.7) and is just as private as d/p/q; the import validator
        // must reject it too (the same shared definition of private the export strips).
        let oth = r#"{"keys":[{"kty":"RSA","n":"abc","e":"AQAB","oth":[{"r":"PRIME","d":"X","t":"CRT"}]}]}"#;
        let oth_doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"private_key_jwt","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"jwks":{oth:?}}}]}}}}"#
        );
        let oth_violations = validate_document(oth_doc.as_bytes()).expect_err("rejected");
        assert!(
            oth_violations.iter().any(|v| v.path.ends_with("/oth")),
            "a multi-prime RSA oth array must be rejected: {oth_violations:?}"
        );
    }

    #[test]
    fn validate_enumerates_all_violations_not_just_the_first() {
        // Two independent faults: a bad enum and a missing required field, in the
        // SAME element. Both must be reported.
        let doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"resource_server":[{{"token_format":"bogus"}}]}}}}"#
        );
        let violations = validate_document(doc.as_bytes()).expect_err("rejected");
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/resource_server/0/audience"),
            "missing audience must be reported: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/resource_server/0/token_format"),
            "bad token_format must be reported: {violations:?}"
        );
    }

    #[test]
    fn validate_rejects_unknown_resource_type_key() {
        let doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"signing_key":[]}}}}"#
        );
        let violations = validate_document(doc.as_bytes()).expect_err("rejected");
        assert!(
            violations
                .iter()
                .any(|v| v.path == "/resources/signing_key"),
            "an environment-identity type key must be rejected: {violations:?}"
        );
    }

    #[test]
    fn project_jwks_strips_every_private_parameter() {
        // A JWK Set carrying an RSA private key (d/p/q/dp/dq/qi) and an EC private
        // key (d) alongside their public halves. The stored `jwks` column can hold
        // exactly this: `jose`'s trusted-key parse ignores private members, so a
        // private-bearing set is accepted and persisted verbatim.
        // The RSA key also carries `oth` (RFC 7518 6.3.2.7 multi-prime): each entry's
        // `r` is an additional PRIME FACTOR of the modulus and is as secret as p/q.
        let private = r#"{"keys":[
            {"kty":"RSA","kid":"r1","use":"sig","alg":"RS256","n":"PUB-N","e":"AQAB",
             "d":"RSA-D-SECRET","p":"RSA-P-SECRET","q":"RSA-Q-SECRET",
             "dp":"RSA-DP-SECRET","dq":"RSA-DQ-SECRET","qi":"RSA-QI-SECRET",
             "oth":[{"r":"OTH-R-SECRET","d":"OTH-D-SECRET","t":"OTH-T-SECRET"}]},
            {"kty":"EC","kid":"e1","crv":"P-256","x":"EC-X","y":"EC-Y","d":"EC-D-SECRET"}
        ]}"#;

        // Prove the LEAK exists on a verbatim copy: the raw column carries the
        // private material, so copying it into a snapshot would leak it.
        assert!(private.contains("RSA-D-SECRET") && private.contains("EC-D-SECRET"));

        let projected = project_jwks_public(Some(private.to_string())).expect("projected");

        // None of the private VALUES survive the projection.
        for secret in [
            "RSA-D-SECRET",
            "RSA-P-SECRET",
            "RSA-Q-SECRET",
            "RSA-DP-SECRET",
            "RSA-DQ-SECRET",
            "RSA-QI-SECRET",
            "OTH-R-SECRET",
            "OTH-D-SECRET",
            "OTH-T-SECRET",
            "EC-D-SECRET",
        ] {
            assert!(
                !projected.contains(secret),
                "private material {secret:?} leaked into the projected jwks: {projected}"
            );
        }

        // No private PARAMETER key survives either (the shared definition of
        // "private" the validator scans for).
        let parsed: serde_json::Value = serde_json::from_str(&projected).expect("valid json");
        let mut found = Vec::new();
        super::scan_private_params(&parsed, "", &PRIVATE_JWK_PARAMS, &mut found);
        assert!(found.is_empty(), "a private parameter survived: {found:?}");

        // The public members are preserved intact.
        for public in ["PUB-N", "AQAB", "EC-X", "EC-Y", "RS256", "P-256"] {
            assert!(
                projected.contains(public),
                "public member {public:?} was dropped: {projected}"
            );
        }

        // The projected set embedded in a client element passes the validator: export
        // and import agree (round-trip clean), which a verbatim copy did NOT.
        let doc = format!(
            r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"cli_x","display_name":"X","token_endpoint_auth_method":"private_key_jwt","redirect_uris":[],"post_logout_redirect_uris":[],"frontchannel_logout_session_required":false,"consent_mode":"explicit","skip_consent":false,"store_skipped_consent":false,"require_pushed_authorization_requests":false,"require_auth_time":false,"jwks":{projected:?}}}]}}}}"#
        );
        validate_document(doc.as_bytes()).expect("projected jwks validates");
    }

    #[test]
    fn project_jwks_drops_symmetric_keys_and_preserves_public_sets() {
        // A symmetric `oct` key is all-secret: the whole element is dropped.
        let with_oct = r#"{"keys":[
            {"kty":"oct","kid":"s1","k":"SYMMETRIC-SECRET-K"},
            {"kty":"OKP","kid":"o1","crv":"Ed25519","x":"OKP-X-PUBLIC"}
        ]}"#;
        let projected = project_jwks_public(Some(with_oct.to_string())).expect("projected");
        assert!(
            !projected.contains("SYMMETRIC-SECRET-K") && !projected.contains("\"oct\""),
            "the symmetric key must be dropped entirely: {projected}"
        );
        assert!(
            projected.contains("OKP-X-PUBLIC"),
            "the public OKP key must survive: {projected}"
        );

        // A purely-public set survives with all members present.
        let public = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
        let projected_public = project_jwks_public(Some(public.to_string())).expect("projected");
        let a: serde_json::Value = serde_json::from_str(public).unwrap();
        let b: serde_json::Value = serde_json::from_str(&projected_public).unwrap();
        assert_eq!(a, b, "a purely-public jwks must be preserved intact");

        // Absent or unparseable input yields no key material.
        assert_eq!(project_jwks_public(None), None);
        assert_eq!(project_jwks_public(Some("not json".to_string())), None);
    }

    #[test]
    fn validate_rejects_non_json() {
        let violations = validate_document(b"not json").expect_err("rejected");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "");
    }
}
