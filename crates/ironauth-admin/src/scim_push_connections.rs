// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OUTBOUND SCIM connection management surface (issue #137).
//!
//! # The mirror of `scim_connections`, and every difference is the direction
//!
//! Inbound, an operator mints a bearer token that lets an identity provider write INTO an
//! organization. Outbound, an operator points IronAuth at somebody else's SCIM server so this
//! environment's directory is pushed there. Three consequences shape this module:
//!
//! NO RESPONSE EVER CARRIES A CREDENTIAL. The inbound create returns a token exactly once,
//! because it mints one; this create returns nothing secret at all, because it mints nothing.
//! The connection NAMES an environment secret and the value is resolved at push time, so there
//! is no plaintext for a response, a listing, or an idempotency replay to leak. That is a
//! property of the model rather than care taken here.
//!
//! THE BASE URL MUST BE https, AND THAT IS CHECKED AT CONFIGURATION TIME. `ironauth-fetch`
//! defaults `allow_plaintext_http` off, so a stored `http://` URL would fail at every push
//! instead of once, at the moment an operator could still fix it. A configuration surface that
//! accepts a value the runtime will always refuse is a surface that defers its own error to the
//! worst possible time.
//!
//! THE SCOPE FILTERS MUST PARSE. They are RFC 7644 filters deciding which users and groups this
//! connection pushes, and an unparseable one stored here would fail on every pass forever. The
//! parser is `ironauth-scim`'s, the same one the inbound surface runs, so a filter accepted here
//! is one the push worker can evaluate.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewScimPushConnection, ScimDeletionPolicy,
    ScimPushConnectionId, ScimWriteMode, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::ApiError;
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One outbound connection, as the management surface renders it.
///
/// THE SECRET NAME IS HERE AND THE SECRET IS NOT, which is the whole point of naming one: this
/// view has nothing to redact, because the row it renders holds nothing to redact.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimPushConnectionView {
    /// The non-secret `spc_` handle. Every other operation names the connection by this.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// The downstream SCIM base URL.
    pub base_url: String,
    /// The NAME of the environment secret holding the bearer token.
    pub credential_secret_name: String,
    /// How IronAuth attributes map onto the downstream schema.
    #[schema(value_type = Object)]
    pub attribute_mapping: serde_json::Value,
    /// The RFC 7644 filter deciding which users are pushed, absent when all of them are.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_scope_filter: Option<String>,
    /// The same for groups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_scope_filter: Option<String>,
    /// `patch` or `put`.
    pub write_mode: String,
    /// `deactivate` or `delete`.
    pub deletion_policy: String,
    /// Whether the worker serves this connection.
    pub active: bool,
    /// Where the initial backfill has reached.
    pub backfill_state: String,
    /// Consecutive failures, which is what a health status is computed from.
    pub consecutive_failures: i32,
    /// The last failure in operator-safe words, absent when there has been none.
    ///
    /// NEVER a downstream response body. An error page can carry anything, including the
    /// credential it was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The last success, in milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at_unix_ms: Option<i64>,
    /// The feed sequence this connection has read through, absent until it starts tailing.
    ///
    /// Criterion 2's "cursor position". Compare with `feed_head_sequence` on the listing to get
    /// LAG. The two are reported separately rather than as one subtracted number, because a
    /// caller shown only "600 behind" cannot tell a connection that has stalled from one whose
    /// feed has simply grown, and those need different responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_sequence: Option<i64>,
    /// When the worker last LOOKED, including polls that found nothing.
    ///
    /// What separates "idle because the feed is quiet" from "idle because the worker is wedged".
    /// `last_success_at_unix_ms` moves only when something was written downstream, so on its own
    /// it cannot tell those apart, and they need opposite responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_polled_at_unix_ms: Option<i64>,
    /// While this is in the future the worker is skipping this connection after a failure.
    ///
    /// Present so an operator seeing a stalled cursor can tell a deliberate backoff from a
    /// stopped worker without reading logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_ms: Option<i64>,
}

/// A page of outbound connections.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimPushConnectionListView {
    /// This organization's outbound connections.
    pub items: Vec<ScimPushConnectionView>,
    /// The cursor for the next page, absent on the last one.
    ///
    /// PRESENT because the operation publishes a `cursor` parameter. It did not, and the
    /// contract advertised `limit` and `cursor` on a listing that had neither a cursor to
    /// return nor a handler that read one: a documented parameter with no field to feed it is
    /// a parameter no client can use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// The newest sequence in this environment's event feed, absent when the feed is empty.
    ///
    /// The OTHER half of criterion 2's lag, reported once for the page rather than per row
    /// because it is the same number for every connection in the scope. A connection's lag is
    /// this minus its own `cursor_sequence`.
    ///
    /// The difference counts FEED POSITIONS, not people waiting to be provisioned. The feed
    /// carries every event the environment emits and a SCIM connection translates almost none of
    /// them: a sign-in, a token issuance and a consent are each one of "600 behind" that will
    /// never produce a request to any downstream. So it says how far back in the feed the worker
    /// is, and a surface built on it should say that rather than imply a queue of unsynced users.
    ///
    /// It is the head the feed will actually SERVE, which is not simply the highest sequence in
    /// the table: the feed withholds an event an older in-flight writer could still precede, and
    /// this number withholds it too. Both sides of the subtraction therefore come from the same
    /// feed, which is what lets a connection that has consumed everything on offer report zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_head_sequence: Option<i64>,
}

/// What a create names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScimPushConnectionRequest {
    /// The operator-facing label, for telling two downstream applications apart.
    pub display_name: String,
    /// The downstream SCIM base URL. Must be https.
    pub base_url: String,
    /// The NAME of an environment secret holding the bearer token. Never the token.
    pub credential_secret_name: String,
    /// How IronAuth attributes map onto the downstream schema. Empty means the core mapping.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    /// An RFC 7644 filter deciding which users are pushed. Absent means all of them.
    #[serde(default)]
    pub user_scope_filter: Option<String>,
    /// The same for groups.
    #[serde(default)]
    pub group_scope_filter: Option<String>,
    /// `patch` or `put`. Defaults to `patch`.
    #[serde(default)]
    pub write_mode: Option<String>,
    /// `deactivate` or `delete`. Defaults to `deactivate`.
    #[serde(default)]
    pub deletion_policy: Option<String>,
}

/// The 201 of a create.
///
/// NOTHING SECRET IS IN IT, and there is nothing that could be.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimPushConnectionCreated {
    /// The non-secret handle.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
}

/// What a pause or resume names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetScimPushActiveRequest {
    /// Whether the worker should serve this connection.
    pub active: bool,
}

fn view(connection: &ironauth_store::ScimPushConnection) -> ScimPushConnectionView {
    ScimPushConnectionView {
        id: connection.id.to_string(),
        display_name: connection.display_name.clone(),
        base_url: connection.base_url.clone(),
        credential_secret_name: connection.credential_secret_name.clone(),
        attribute_mapping: connection.attribute_mapping.clone(),
        user_scope_filter: connection.user_scope_filter.clone(),
        group_scope_filter: connection.group_scope_filter.clone(),
        write_mode: connection.write_mode.as_str().to_owned(),
        deletion_policy: connection.deletion_policy.as_str().to_owned(),
        active: connection.active,
        backfill_state: connection.backfill_state.as_str().to_owned(),
        consecutive_failures: connection.consecutive_failures,
        last_error: connection.last_error.clone(),
        last_success_at_unix_ms: connection
            .last_success_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        cursor_sequence: connection.cursor_sequence,
        last_polled_at_unix_ms: connection
            .last_polled_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        paused_until_unix_ms: connection
            .paused_until_unix_micros
            .map(crate::scim_connections::micros_to_millis),
    }
}

/// What a connection calls one subject downstream, and how that subject's last push went.
///
/// Criterion 2's "per-resource errors". The connection-level health next door answers "is this
/// downstream reachable"; this answers "which PEOPLE are failing, and with what", which is a
/// different question and the one an operator asks second.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ScimPushResourceView {
    /// IronAuth's own id for the subject.
    pub subject_id: String,
    /// `user` or `group`.
    pub resource_type: String,
    /// What the downstream calls it. Server-issued there, opaque here.
    pub downstream_id: String,
    /// The `externalId` this connection sent for the subject.
    ///
    /// Recorded rather than recomputed: a connection's attribute mapping can change what is
    /// sent, and an operator asking "what did we tell them this person was called" wants what
    /// WAS sent, not what would be sent now.
    pub external_id: String,
    /// When this subject was last pushed successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at_unix_ms: Option<i64>,
    /// When this subject last failed to push.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_at_unix_ms: Option<i64>,
    /// When this subject was withdrawn downstream, absent while it is provisioned.
    ///
    /// Present because the link row SURVIVES a withdrawal so a rehire resolves through it. Without
    /// it this listing reported a departed person with a `last_synced_at` and no error, which is
    /// indistinguishable from a healthy one: an operator auditing who still has access would have
    /// read the removed people as present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprovisioned_at_unix_ms: Option<i64>,
    /// What that failure said, truncated to the column's bound.
    ///
    /// Cleared on the next success, because recording a success and clearing the failure are the
    /// same event: a stale error here would make this surface answer a question about the past.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// A page of one connection's per-resource state.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ScimPushResourceListView {
    /// The subjects this connection has provisioned, oldest first.
    pub items: Vec<ScimPushResourceView>,
    /// The cursor for the next page, absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

fn resource_view(link: &ironauth_store::ScimPushLink) -> ScimPushResourceView {
    ScimPushResourceView {
        subject_id: link.subject_id.clone(),
        resource_type: link.resource_type.as_str().to_owned(),
        downstream_id: link.downstream_id.clone(),
        external_id: link.external_id.clone(),
        last_synced_at_unix_ms: link
            .last_synced_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        last_error_at_unix_ms: link
            .last_error_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        deprovisioned_at_unix_ms: link
            .deprovisioned_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        last_error: link.last_error.clone(),
    }
}

/// Refuse a base URL the push worker could never use.
///
/// # Checked here rather than at push time
///
/// `ironauth-fetch` defaults `allow_plaintext_http` off, so an `http://` URL fails on every pass
/// forever. Catching it once, when an operator is looking at the field they just typed, is the
/// difference between a validation error and a connection that silently never works.
fn check_base_url(value: &str) -> Result<String, ApiError> {
    let value = require_non_empty(value, "base_url")?;
    // A TEXT-COLUMN BOUND, not a URL rule, so it stays here: 0189's `octet_length` CHECK would
    // otherwise reach the caller as SQLSTATE 23514 and a 500 nobody predicted.
    if value.len() > MAX_BASE_URL_BYTES {
        return Err(ApiError::BadRequest(format!(
            "invalid_base_url: base_url must be at most {MAX_BASE_URL_BYTES} bytes"
        )));
    }
    // NOT A HAND-WRITTEN GRAMMAR. The first version restated the fetcher's URL rules by hand
    // (scheme prefix, authority split, host emptiness, userinfo, IPv6 brackets) and drifted from
    // them in both directions: it REFUSED `HTTPS://host/scim`, which the fetcher accepts because
    // RFC 3986 makes the scheme case insensitive, and it ACCEPTED `https://host:0/scim` and
    // `https://host:99999/scim`, which the fetcher refuses as malformed. A base URL accepted here
    // and refused there is stored and then fails on every push for ever, which is the exact
    // failure this function's own message says it exists to prevent.
    //
    // `external_issuers.rs` shipped that identical defect against `jwks_uri` and was corrected to
    // call `parse_target`; its comment names the same two divergences. This is the same
    // correction in the outbound SCIM half, not a claim about that one.
    //
    // `parse_target` is also the function the FETCHER itself runs, so agreement is by
    // construction rather than by two copies being kept in step.
    let target = ironauth_fetch::parse_target(&value).map_err(|error| {
        ApiError::BadRequest(format!(
            "invalid_base_url: base_url is not a URL the hardened fetcher can resolve \
             ({error:?}), so the push worker could never reach it"
        ))
    })?;
    if target.scheme != ironauth_fetch::Scheme::Https {
        return Err(ApiError::BadRequest(
            "invalid_base_url: base_url must be an https URL, because the push worker sends a \
             bearer token with authority over somebody else's directory and refuses to send it \
             in clear"
                .to_owned(),
        ));
    }
    // NOT REFUSING A LITERAL ADDRESS HERE, deliberately. `external_issuers.rs` additionally runs
    // `classify` on `target.literal_ip` and refuses a loopback or metadata address at
    // configuration time, and the same argument would apply to a push connection: one pointed at
    // an address the fetcher blocks can never sync.
    //
    // It is left out because it is a BEHAVIOUR CHANGE rather than part of undoing the
    // duplication, and mixing the two makes both harder to review and to revert. An existing
    // test stores `https://[2001:db8::1]/scim/v2`, which `classify` refuses as documentation
    // range, so adding the guard silently changes what this surface accepts. That deserves its
    // own change with its own reasoning about which classes are worth refusing early, given the
    // fetcher refuses them at push time anyway.
    // WHAT `parse_target` DOES NOT EXPRESS, because it is about this caller's own path building
    // rather than about URLs: a base carrying a query or a fragment folds the SCIM path into it,
    // so `/Users` becomes part of a parameter value and every request addresses the base path.
    // `scim_push_transport::join` refuses it too and calls itself the last place that sees both
    // halves; refusing here as well means an operator learns at save time.
    if value.contains('?') || value.contains('#') {
        return Err(ApiError::BadRequest(
            "invalid_base_url: base_url must not carry a query or a fragment, because the SCIM \
             path is appended to it and would be folded into one"
                .to_owned(),
        ));
    }
    Ok(value)
}

/// Refuse a scope filter the push worker could never evaluate.
fn check_filter(value: Option<&str>, field: &'static str) -> Result<Option<String>, ApiError> {
    let Some(value) = value else { return Ok(None) };
    // THE SAME PARSER THE INBOUND SURFACE RUNS, so a filter accepted here is one the worker can
    // evaluate. A second grammar would be a second thing to keep in step.
    ironauth_scim::parse_filter(value).map_err(|_| {
        ApiError::BadRequest(format!(
            "invalid_scope_filter: {field} is not a valid RFC 7644 filter"
        ))
    })?;
    // NO LENGTH CHECK HERE, and its absence is deliberate. One was added and it was DEAD:
    // `parse_filter` opens with its own refusal at 4096 bytes, the same figure, so every value
    // reaching this line had already been proven short enough. The branch could not fire, and
    // the message it would have produced was not the one a caller actually got.
    //
    // A bound whose subject was already bounded is not defence in depth, it is a second number
    // to keep in step with the first.
    Ok(Some(value.to_owned()))
}

/// The longest an operator-supplied LABEL may be, in BYTES.
///
/// The same figure the inbound mirror's handler uses, and the same figure migration 0189 bounds
/// `display_name` at with `octet_length`. TWO BOUNDS ON ONE VALUE MUST AGREE ON THE UNIT: the
/// column counted CHARACTERS first while this counts bytes, which leaves a band -- a 200
/// character string of three-byte characters -- where one refuses and the other does not.
///
/// It is NOT the bound for `credential_secret_name`. That field is an `environment_secrets` key
/// and [`check_secret_name`] applies the secret store's own rule to it; a label bound would let
/// a name be stored that can never resolve.
const MAX_LABEL_BYTES: usize = 252;

/// The longest a serialised attribute mapping may be, in bytes.
///
/// Generous: a mapping is one entry per attribute a downstream schema has, and no real schema
/// approaches this. It exists to bound the row, not to constrain a mapping anyone would write.
const MAX_MAPPING_BYTES: usize = 16 * 1024;

/// The longest base URL, in bytes. Longer than a label because a SCIM base URL legitimately
/// carries a tenant path segment, and shorter than anything that would make a row expensive.
const MAX_BASE_URL_BYTES: usize = 2048;

/// Non-empty and bounded, refused HERE so the column's CHECK is never what a caller meets.
///
/// A CHECK violation is SQLSTATE 23514, which `is_unique_violation` does not match, so it falls
/// through to `ApiError::Internal`: a 500 from a long string in a request body. The inbound
/// mirror records being caught by exactly that with an EMPTY name.
fn check_label(value: &str, field: &str, max: usize) -> Result<String, ApiError> {
    let value = require_non_empty(value, field)?;
    // A NUL, for the reason `check_attribute_mapping` refuses one: a Postgres `text` column
    // cannot hold `U+0000` either, so without this the same 22P05 reaches the caller as a 500
    // from a plain string field. The mapping guard was added first and covered only the jsonb
    // column, which left the four text columns beside it with the hazard it was written for.
    if value.contains('\0') {
        return Err(ApiError::BadRequest(format!(
            "invalid_{field}: {field} must not contain a NUL character, which the column \
             cannot store"
        )));
    }
    if value.len() > max {
        return Err(ApiError::BadRequest(format!(
            "invalid_{field}: {field} must be at most {max} bytes"
        )));
    }
    Ok(value)
}

/// The credential's secret name must be a name the secret store can actually resolve.
///
/// NOT `check_label`. Round two bounded this field with the operator-facing LABEL rule -- 252
/// bytes, any characters -- and that is the wrong rule for it: this is an
/// `environment_secrets` KEY, and `ironauth_store::esv::name_is_valid` is what the secret store
/// applies on write. A name outside that alphabet can be stored on a connection and then never
/// resolve, so the push fails at every attempt for a reason configured long before and visible
/// nowhere near it.
///
/// Calling the store's own predicate rather than restating it: a rule copied here would be a
/// second place for the alphabet to live, and the two would drift on the first change.
/// The prefix a connection's credential secret must carry.
///
/// # This is a confinement, not a naming convention
///
/// The environment-secret store is WRITE-ONLY by design: `setSecret` stores a value and no
/// endpoint returns one, so a principal with `management.write` cannot read a secret it did not
/// supply. A push connection names a secret and sends its plaintext to a base URL the same
/// principal chose, which turns that store into a read oracle: point a connection at any secret
/// name, at a server you control, and the worker delivers it as a bearer token.
///
/// It was latent while nothing ran the worker. The scheduler is what makes it reachable, so the
/// bound goes in with it.
///
/// A prefix rather than an allowlist because the set is not knowable here: an operator names
/// their own secrets. What the prefix buys is that a connection can only ever name a secret
/// somebody deliberately put in the connection namespace, so a database password, a signing key
/// or an upstream client secret is out of reach whatever the connection says.
pub const CREDENTIAL_SECRET_PREFIX: &str = "scim_push_";

fn check_secret_name(value: &str) -> Result<String, ApiError> {
    let value = require_non_empty(value, "credential_secret_name")?;
    if !ironauth_store::esv::name_is_valid(&value) {
        return Err(ApiError::BadRequest(format!(
            "invalid_credential_secret_name: credential_secret_name must be at most {} ASCII \
             letters, digits, underscore, dot or hyphen, which is what an environment secret \
             name may be",
            ironauth_store::esv::MAX_NAME_LEN
        )));
    }
    if !value.starts_with(CREDENTIAL_SECRET_PREFIX) {
        return Err(ApiError::BadRequest(format!(
            "invalid_credential_secret_name: credential_secret_name must begin with \
             {CREDENTIAL_SECRET_PREFIX:?}. A connection sends the named secret to its base URL as \
             a bearer token, so a connection that could name any secret would make the \
             write-only secret store readable by anyone who can configure one"
        )));
    }
    Ok(value)
}

/// The attribute mapping is a JSON OBJECT, and a bounded one.
///
/// Checked HERE, before the write, for the same reason the vocabularies are: the column carries
/// a `jsonb_typeof(...) = 'object'` CHECK, and a caller that sent `[1, 2, 3]` would otherwise
/// meet that CHECK as a database error rendered 500. A malformed body is the caller's mistake
/// and deserves to be told so.
///
/// BOUNDED for the reason 0189 gives for bounding the other three: without one the only limit is
/// the request body limit, and a single row can carry megabytes. Round two wrote that sentence
/// into the migration and then left this column, and both scope filters, unbounded on both
/// sides -- the same hazard the sentence names, in the fields it did not reach.
/// Whether any string anywhere in this JSON value contains a NUL.
///
/// Recursive over the VALUE rather than a search of its rendered form: the rendered form escapes
/// a backslash, so searching it for `\u0000` also matches a legal string whose text merely spells
/// that escape. This asks the question about the data.
fn contains_nul(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => text.contains('\0'),
        serde_json::Value::Array(items) => items.iter().any(contains_nul),
        serde_json::Value::Object(fields) => fields
            .iter()
            .any(|(k, v)| k.contains('\0') || contains_nul(v)),
        _ => false,
    }
}

fn check_attribute_mapping(
    value: Option<serde_json::Value>,
) -> Result<serde_json::Value, ApiError> {
    let value = value.unwrap_or_else(|| serde_json::json!({}));
    if !value.is_object() {
        return Err(ApiError::BadRequest(
            "invalid_attribute_mapping: attribute_mapping must be a JSON object".to_owned(),
        ));
    }
    // Measured on the SERIALISED form, which is what the column stores and therefore what the
    // bound has to be about. Counting keys would bound the wrong thing: one key with a
    // megabyte value passes a key count and is exactly the row this refuses.
    // A NUL ANYWHERE IN THE DOCUMENT, refused here. `jsonb` cannot store `U+0000` in a string
    // -- Postgres raises 22P05 -- and `is_object` says nothing about it, so a mapping with one
    // reached the column and became a 500. That is the same failure this whole function was
    // added to prevent, one level deeper: valid JSON that `jsonb` will not accept.
    //
    // MEASURED ON THE VALUE, not on the rendered JSON. The first version searched the serialised
    // form for the six characters `\u0000`, and serde escapes a backslash as `\\`, so a mapping
    // whose text is literally backslash-u-zero-zero-zero-zero -- containing no NUL at all --
    // rendered as `"\\u0000"` and was refused. A guard that refuses a legal value is as wrong as
    // one that admits an illegal one.
    let rendered = serde_json::to_string(&value).map_err(|_| ApiError::Internal)?;
    if contains_nul(&value) {
        return Err(ApiError::BadRequest(
            "invalid_attribute_mapping: attribute_mapping must not contain a NUL character, \
             which jsonb cannot store"
                .to_owned(),
        ));
    }
    if rendered.len() > MAX_MAPPING_BYTES {
        return Err(ApiError::BadRequest(format!(
            "invalid_attribute_mapping: attribute_mapping must serialise to at most \
             {MAX_MAPPING_BYTES} bytes"
        )));
    }
    Ok(value)
}

/// Map a stored vocabulary word, refusing anything outside it.
///
/// VALIDATED HERE, not by catching the column's CHECK. An earlier module in this crate mapped
/// every `StoreError::Database` onto a 400 naming the field, so a revoked grant or a full disk
/// told the caller their input was wrong -- and the sweep that looks for missing grants passed
/// against a handler that was broken.
fn check_write_mode(value: Option<&str>) -> Result<ScimWriteMode, ApiError> {
    match value {
        None | Some("patch") => Ok(ScimWriteMode::Patch),
        Some("put") => Ok(ScimWriteMode::Put),
        Some(_) => Err(ApiError::BadRequest(
            "invalid_write_mode: write_mode must be patch or put".to_owned(),
        )),
    }
}

/// The same for the deletion policy.
fn check_deletion_policy(value: Option<&str>) -> Result<ScimDeletionPolicy, ApiError> {
    match value {
        None | Some("deactivate") => Ok(ScimDeletionPolicy::Deactivate),
        Some("delete") => Ok(ScimDeletionPolicy::Delete),
        Some(_) => Err(ApiError::BadRequest(
            "invalid_deletion_policy: deletion_policy must be deactivate or delete".to_owned(),
        )),
    }
}

/// `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections`
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections",
    operation_id = "listScimPushConnections",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ListQuery
    ),
    responses(
        (status = 200, description = "The organization's outbound SCIM connections", body = ScimPushConnectionListView),
        (status = 400, description = "A malformed cursor or limit", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not read this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scim_push_connections(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102). READ, not WriteConfig: a listing carries no
    // credential, so it is a strictly smaller capability than pointing one somewhere.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    // CURSOR PAGINATED, like every sibling listing on this surface. It was not: the operation
    // published `limit` and `cursor` into the committed contract and both generated clients,
    // bound the query to `_query`, and passed a fixed page size -- so the two parameters did
    // nothing and an organization's connections past the cap were unreachable. The inbound
    // mirror shipped exactly this defect and was corrected for it; this is the same correction
    // in the outbound half, not a claim about the inbound one.
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let connections = state
        .store()
        .scoped(scope)
        .scim_push_connections()
        .list_for_org(&org_id, page.fetch_limit(), page.after())
        .await
        .map_err(|_| ApiError::Internal)?;
    let (connections, next_cursor) = page.finish(connections, |connection| {
        (connection.created_at_unix_micros, connection.id.to_string())
    });
    let body = serde_json::to_string(&ScimPushConnectionListView {
        items: connections.iter().map(view).collect(),
        next_cursor,
        // READ ONCE FOR THE PAGE. It is the same number for every connection in the scope, so a
        // per-row query would be one round trip per connection to learn one fact.
        feed_head_sequence: state
            .store()
            .scoped(scope)
            .outbox()
            .newest_sequence()
            .await
            .map_err(|_| ApiError::Internal)?,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections/{connection_id}/resources`
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections/{connection_id}/resources",
    operation_id = "listScimPushResources",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "Outbound SCIM connection identifier"),
        ListQuery
    ),
    responses(
        (status = 200, description = "The subjects this connection has provisioned, with per-resource error state", body = ScimPushResourceListView),
        (status = 400, description = "A malformed cursor or limit", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not read this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization or connection", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scim_push_resources(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102). READ, like the connection listing beside it: this
    // carries no credential and changes nothing, so it is a strictly smaller capability than
    // pointing a connection somewhere.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    let id = ScimPushConnectionId::parse_in_scope(&connection_id, &scope)
        .map_err(|_| ApiError::NotFound)?;

    // THE CONNECTION IS RESOLVED THROUGH THE ORGANIZATION, not merely parsed. A caller holding a
    // credential for organization A must not read organization B's provisioning state by naming
    // B's connection id in A's path: the id is unguessable, but "unguessable" is not an
    // authorization check, and the whole point of the org confinement surface is that the
    // organization comes from the credential rather than the request.
    let connection = state
        .store()
        .scoped(scope)
        .scim_push_connections()
        .find_in_org(&org_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let links = state
        .store()
        .scoped(scope)
        .scim_push_links()
        .list_for_connection(&connection.id, page.fetch_limit(), page.after())
        .await
        .map_err(|_| ApiError::Internal)?;
    let (links, next_cursor) = page.finish(links, |link| {
        (link.created_at_unix_micros, link.id.to_string())
    });
    let body = serde_json::to_string(&ScimPushResourceListView {
        items: links.iter().map(resource_view).collect(),
        next_cursor,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections`
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections",
    operation_id = "createScimPushConnection",
    tag = "scim",
    request_body = CreateScimPushConnectionRequest,
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. A retry under the same key returns the original response without creating a second connection"),
    ),
    responses(
        (status = 201, description = "The connection was created", body = ScimPushConnectionCreated),
        (status = 400, description = "A malformed body, base URL, filter or vocabulary word", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not write this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
        (status = 409, description = "A concurrent request carried the same Idempotency-Key", body = crate::error::ErrorBody),
        (status = 422, description = "The Idempotency-Key was reused with a different request", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_scim_push_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102). WriteConfig, not WriteCredentials: this mints
    // nothing. It names an environment secret that already exists, and whoever created THAT
    // needed the credential permission.
    principal.require_permission(ManagementPermission::WriteConfig)?;

    // IDEMPOTENT, like every other POST on this surface. `idempotency.rs` opens with the
    // invariant in its first line -- "The header is required on every POST" -- and this handler
    // did not honour it: a lost 201 leaves a connection created, and the retry creates a second
    // one pointed at the same downstream.
    //
    // NOT "the one 201-returning create on the management API without a key", which an earlier
    // version of this comment claimed. `impersonation::authorize_user_impersonation` is
    // another. Being the only one was never the reason; the invariant is.
    //
    // The replay check runs BEFORE the organization is resolved, as the inbound mirror's does,
    // so a retry of a request whose organization has since been deleted still returns the
    // original response rather than a 404 for work that succeeded.
    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let request: CreateScimPushConnectionRequest = parse_json(&body)?;
    // BOUNDED as well as non-empty. Migration 0189 bounds these two columns, and without the
    // check here a long label reaches the CHECK, which is SQLSTATE 23514 and falls through to
    // `ApiError::Internal`: a 500 from a request body. Same figure, same unit (bytes).
    let display_name = check_label(&request.display_name, "display_name", MAX_LABEL_BYTES)?;
    let base_url = check_base_url(&request.base_url)?;
    let credential_secret_name = check_secret_name(&request.credential_secret_name)?;
    let user_scope_filter =
        check_filter(request.user_scope_filter.as_deref(), "user_scope_filter")?;
    let group_scope_filter =
        check_filter(request.group_scope_filter.as_deref(), "group_scope_filter")?;
    let write_mode = check_write_mode(request.write_mode.as_deref())?;
    let deletion_policy = check_deletion_policy(request.deletion_policy.as_deref())?;
    let attribute_mapping = check_attribute_mapping(request.attribute_mapping)?;

    let id = ScimPushConnectionId::generate(state.env(), &scope);
    // THE RESPONSE IS BUILT BEFORE THE WRITE, because the idempotency record stores it in the
    // same transaction: a replay must return the ORIGINAL bytes, so they have to exist by the
    // time the row does.
    let created = ScimPushConnectionCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
    };
    let stored_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;
    let pending = created_event(&state, scope, &id, &org_id, &base_url);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, which is a different column from the audit detail
        // this write already carries. `audit_log.organization_id` is what a per-organization
        // log stream selects on, so without this the org whose directory is being re-pointed
        // sees none of it on its own stream.
        .in_organization(org_id)
        .scim_push_connections()
        .create(
            state.env(),
            NewScimPushConnection {
                id: &id,
                organization_id: &org_id,
                display_name: &display_name,
                base_url: &base_url,
                credential_secret_name: &credential_secret_name,
                attribute_mapping: &attribute_mapping,
                user_scope_filter: user_scope_filter.as_deref(),
                group_scope_filter: group_scope_filter.as_deref(),
                write_mode,
                deletion_policy,
            },
            // IN THE SAME TRANSACTION as the row, which is why it is a parameter rather than a
            // second call: a record written afterwards leaves a window in which the connection
            // exists and the retry that created it can still create a second one.
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &stored_body,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, stored_body)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict("connection_exists".to_owned())),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        // THE IDEMPOTENCY RACE THE RECORD EXISTS TO CLOSE: two requests carrying one key arrive
        // together, both pass `replay_if_stored` because neither sees a row yet, and the loser
        // meets the winner's primary key in `idempotency_keys`. Its whole transaction rolls
        // back, so no second connection and no orphaned event exist -- and then it RE-READS and
        // returns the winner's committed 201, which is what the other 44 sites on this surface
        // do and what the caller actually wants: the id that was minted.
        //
        // Adding the Idempotency-Key created the obligation to handle its own race, and the
        // first version did not: the variant fell into the wildcard below, so the one condition
        // the header was added for was the one condition that answered 500.
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &idem_key, &fingerprint)
                .await
        }
        // EVERYTHING ELSE IS A 500, deliberately. Mapping a bare database error onto a 400
        // naming a field is how a revoked grant or a full disk told a caller their input was
        // wrong, and how the sweep that looks for missing grants passed against a broken
        // handler.
        //
        // This arm once carried "Every input this route rejects is rejected above, before the
        // write", which the idempotency record made FALSE: a key collision is not an input, it
        // is a race, and it reached this arm. It has its own arm now and the sentence is gone.
        Err(_) => Err(ApiError::Internal),
    }
}

/// `PUT .../scim-push-connections/{connection_id}/active`
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections/{connection_id}/active",
    operation_id = "setScimPushConnectionActive",
    tag = "scim",
    request_body = SetScimPushActiveRequest,
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "Outbound connection identifier"),
    ),
    responses(
        (status = 204, description = "The connection was paused or resumed"),
        (status = 400, description = "A malformed body", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not write this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such organization or connection", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_scim_push_connection_active(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102). WriteConfig: pausing or removing a connection
    // changes what the push worker does, which is configuration rather than a credential.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let request: SetScimPushActiveRequest = parse_json(&body)?;
    // PARSED IN SCOPE. An id from another scope is a 404 rather than a refusal that says the
    // connection exists somewhere.
    let id = ScimPushConnectionId::parse_in_scope(&connection_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    let pending = active_changed_event(&state, scope, &id, &org_id, request.active);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, which is a different column from the audit detail
        // this write already carries. `audit_log.organization_id` is what a per-organization
        // log stream selects on, so without this the org whose directory is being re-pointed
        // sees none of it on its own stream.
        .in_organization(org_id)
        .scim_push_connections()
        .set_active(
            state.env(),
            &org_id,
            &id,
            request.active,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;
    Ok(no_content())
}

/// `DELETE .../scim-push-connections/{connection_id}`
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-push-connections/{connection_id}",
    operation_id = "deleteScimPushConnection",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "Outbound connection identifier"),
    ),
    responses(
        (status = 204, description = "The connection was deleted"),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not write this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such organization or connection", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_scim_push_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102). WriteConfig: pausing or removing a connection
    // changes what the push worker does, which is configuration rather than a credential.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = ScimPushConnectionId::parse_in_scope(&connection_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    let pending = deleted_event(&state, scope, &id, &org_id);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, which is a different column from the audit detail
        // this write already carries. `audit_log.organization_id` is what a per-organization
        // log stream selects on, so without this the org whose directory is being re-pointed
        // sees none of it on its own stream.
        .in_organization(org_id)
        .scim_push_connections()
        .delete(
            state.env(),
            &org_id,
            &id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;
    Ok(no_content())
}

/// The `scim_push_connection.created` envelope.
///
/// EVERY management write on this surface announces itself, which is what
/// `scripts/producer-coverage.py` measures against the mounted write surface. The first version
/// of this module announced nothing on any of its three writes, so a consumer watching for
/// "where is this organization's directory going" saw a connection appear only by polling.
fn created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimPushConnectionId,
    organization_id: &ironauth_store::OrganizationId,
    base_url: &str,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_push_connection.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_push_connection_id": subject,
            "organization_id": organization_id.to_string(),
            "base_url": base_url,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_push_connection.active_changed` envelope.
fn active_changed_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimPushConnectionId,
    organization_id: &ironauth_store::OrganizationId,
    active: bool,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_push_connection.active_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_push_connection_id": subject,
            "organization_id": organization_id.to_string(),
            "active": active,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_push_connection.deleted` envelope.
fn deleted_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimPushConnectionId,
    organization_id: &ironauth_store::OrganizationId,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_push_connection.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_push_connection_id": subject,
            "organization_id": organization_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}
