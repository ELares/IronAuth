// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal risk-engine store value types (issue #79).
//!
//! The engine logic (the signals, the deterministic LOW/MED/HIGH scoring rule, and the
//! block/challenge/notify dispatch) lives in the `ironauth-oidc` crate; this module
//! carries only the persistence-layer inputs and views the [`crate::repository`]
//! `RiskRepo` / `ActingRiskRepo` read and write. The score and action are stored as
//! stable wire strings so the store never depends on the engine's enums.

use crate::id::{RiskDecisionId, UserId};

/// A third-party risk signal to INGEST (issue #82, PR 1): the verified fields of a signed
/// Security Event Token an external fraud/risk source delivered. The repository blind-indexes
/// `subject_raw` before it lands (the raw external subject is never a plaintext column) and
/// records the row keyed by `(source, source_jti)` for idempotent single delivery. Nothing
/// here carries a resolved action: a signal is a policy input, never a verdict.
#[derive(Debug, Clone, Copy)]
pub struct NewRiskSignal<'a> {
    /// The signal source identity (the SET `iss` the signature verified under).
    pub source: &'a str,
    /// The free-text, URI-capable event-type token (a CAEP event-type URI fits verbatim).
    pub signal_type: &'a str,
    /// The RFC 9493 Subject Identifier format the source asserted (a closed set).
    pub subject_format: &'a str,
    /// The RAW external subject the source asserted. Blind-indexed by the repository before
    /// it lands; NEVER stored as a plaintext column.
    pub subject_raw: &'a str,
    /// The resolved local `usr_` id the external subject maps to, or `None` when it maps to
    /// no local account (an inert row the engine never reads for any real subject).
    pub resolved_subject: Option<&'a UserId>,
    /// The tagged signal body `{kind:"verdict"|"score", ...}` serialized as a JSON document.
    pub payload_json: &'a str,
    /// The source's event instant (CAEP `event_timestamp`) in microseconds since the epoch:
    /// the freshness input the engine compares against the per-source max age.
    pub event_timestamp_micros: i64,
    /// The SET `jti`: the single-delivery dedup key.
    pub source_jti: &'a str,
}

/// A fresh third-party risk signal read for a subject (issue #82, PR 1), one contribution
/// the #79 engine maps to a weighted `SignalOutcome`. Every field derives from the stored
/// row; the raw external subject is never returned (only its keyed blind index was stored).
#[derive(Debug, Clone)]
pub struct RiskSignalView {
    /// The signal source identity (the enabled `RiskConfig` source the engine keys policy on).
    pub source: String,
    /// The free-text event-type token.
    pub signal_type: String,
    /// The tagged signal body as a JSON document (mapped to a `RiskLevel` by the source config).
    pub payload_json: String,
    /// The source's event instant in microseconds since the epoch (the freshness input).
    pub event_timestamp_unix_micros: i64,
}

/// A login-geo observation to record (issue #79): the observed peer IP, the resolved
/// coarse location (a small JSON document of latitude, longitude, and optional ASN),
/// and the observed User-Agent at a login, plus the login instant. The three PII
/// fields are sealed under the scope DEK by the repository; nothing here is stored in
/// the clear.
#[derive(Debug, Clone, Copy)]
pub struct NewLoginGeo<'a> {
    /// The observed peer IP at login (sealed at rest).
    pub ip: &'a str,
    /// The resolved coarse location as a JSON document (sealed at rest). Opened by the
    /// impossible-travel signal to compute geo-velocity.
    pub geo_json: &'a str,
    /// The observed User-Agent at login (sealed at rest).
    pub user_agent: &'a str,
    /// The login instant in microseconds since the epoch (via `env.clock()`).
    pub observed_at_micros: i64,
}

/// The previous login-geo observation for a subject (issue #79), opened from the sealed
/// row. The impossible-travel signal reads `geo_json` and `observed_at_unix_micros` as
/// the "from" point of the geo-velocity computation.
#[derive(Debug, Clone)]
pub struct LoginGeoView {
    /// The resolved coarse location as a JSON document, decrypted from the sealed
    /// column.
    pub geo_json: String,
    /// The instant the observation was recorded, in microseconds since the epoch.
    pub observed_at_unix_micros: i64,
}

/// A risk decision to persist (issue #79): the LOW/MED/HIGH score, the dispatched action
/// verb, and the enumerated contributing signals as a jsonb document. The score and
/// action are stable wire strings the CHECK constraints pin to their closed sets; the
/// signals document carries NO plaintext PII.
#[derive(Debug, Clone, Copy)]
pub struct NewRiskDecision<'a> {
    /// The LOW/MED/HIGH score as a wire string (`low` / `med` / `high`).
    pub score: &'a str,
    /// The dispatched action verb (`allow` / `block` / `challenge` / `notify`).
    pub action: &'a str,
    /// The enumerated contributing signals and their typed values, as a JSON document.
    pub signals_json: &'a str,
    /// A COMPACT, operator-safe enumerated signal summary (`kind:level` pairs, PII-free)
    /// written to the audit detail alongside the score and action, so a sampled decision is
    /// reconstructable from the audit trail ALONE even if the append-only `risk_decisions`
    /// row is pruned. Carries only signal kinds and levels, never the raw IP/geo/counts.
    pub signals_summary: &'a str,
    /// The request correlation id the decision belongs to, if any.
    pub correlation_id: Option<&'a str>,
}

/// A persisted risk decision (issue #79), read back for the account view, audit
/// sampling, or reconstruction. Every field derives from the stored row.
#[derive(Debug, Clone)]
pub struct RiskDecisionView {
    /// The `rsk_` decision id.
    pub id: RiskDecisionId,
    /// The `usr_` subject the login was scored for.
    pub subject: String,
    /// The LOW/MED/HIGH score as a wire string.
    pub score: String,
    /// The dispatched action verb.
    pub action: String,
    /// The enumerated contributing signals as a JSON document.
    pub signals_json: String,
    /// When the decision was recorded, in microseconds since the epoch.
    pub created_at_unix_micros: i64,
}

/// A disavowal token to mint (issue #79): the SHA-256 digest of the single-use secret,
/// the sessions the disavowal revokes, the decision it descends from, and the expiry.
#[derive(Debug, Clone, Copy)]
pub struct NewDisavowalToken<'a> {
    /// The SHA-256 digest of the token's high-entropy secret (server-side state).
    pub token_digest: &'a [u8],
    /// The `rsk_` decision this disavowal descends from, if any.
    pub decision_id: Option<&'a str>,
    /// The `ses_` sessions the disavowal revokes (the sessions in question).
    pub session_ids: &'a [String],
    /// The token expiry in microseconds since the epoch.
    pub expires_at_micros: i64,
}

/// A resolved, live disavowal token (issue #79), returned by a lookup before it is
/// consumed. Names the subject and the sessions the disavowal must revoke.
#[derive(Debug, Clone)]
pub struct DisavowalResolution {
    /// The `dis_` disavowal id.
    pub id: String,
    /// The `usr_` subject the disavowal is for.
    pub subject: UserId,
    /// The `ses_` sessions the disavowal revokes.
    pub session_ids: Vec<String>,
}
