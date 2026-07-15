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

/// The resource types a snapshot carries.
///
/// This MUST equal exactly the set [`classify`] marks
/// [`ResourceClassification::Promotable`]. The `snapshot_types_are_exactly_the_promotable_set`
/// test enforces that equality, so this constant cannot drift from the
/// classification: a new promotable type fails the test until it is covered here
/// (and by the export), and an environment-identity or runtime type can never be
/// added without failing it. This is the live binding between the snapshot and the
/// single source of truth, not a hand-maintained parallel list.
pub const SNAPSHOT_RESOURCE_TYPES: [ResourceType; 3] = [
    ResourceType::Client,
    ResourceType::ResourceServer,
    ResourceType::DcrPolicy,
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

    Ok(Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
        resources: SnapshotResources {
            client: clients,
            resource_server,
            dcr_policy,
        },
    })
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
const PRIVATE_JWK_PARAMS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

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
        // Keys sorted: resources before schema_version.
        assert_eq!(
            text,
            "{\"resources\":{\"client\":[],\"dcr_policy\":[],\"resource_server\":[]},\
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
        let private = r#"{"keys":[
            {"kty":"RSA","kid":"r1","use":"sig","alg":"RS256","n":"PUB-N","e":"AQAB",
             "d":"RSA-D-SECRET","p":"RSA-P-SECRET","q":"RSA-Q-SECRET",
             "dp":"RSA-DP-SECRET","dq":"RSA-DQ-SECRET","qi":"RSA-QI-SECRET"},
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
