// SPDX-License-Identifier: MIT OR Apache-2.0

//! Headless flow state value types (issue #84).
//!
//! These are the persistence layer inputs and views for the `flows` table: the one
//! short lived, single use completion row that holds an in progress journey's position
//! between submissions. The `state` is opaque application JSON (the serialized state
//! machine position plus the node scratch the next render needs), owned entirely by the
//! flow engine in the OIDC crate. The `transient_payload` is arbitrary client supplied
//! context carried through the flow; it lives ONLY here and is NEVER copied onto an
//! identity table, so it cannot persist on the identity by construction.

/// A flow row to persist at creation (issue #84). The `state` and `transient_payload`
/// are already serialized JSON the repository stores verbatim; the `submit_token` is the
/// API transport CSRF handle the repository stores and later rotates.
#[derive(Debug, Clone, Copy)]
pub struct NewFlow<'a> {
    /// The journey this row drives: `login` | `registration` | `mfa` | `recovery`.
    pub journey: &'a str,
    /// The transport this flow was created on: `browser` | `api`. Immutable after
    /// creation.
    pub transport: &'a str,
    /// The serialized state machine position plus node scratch (opaque application JSON).
    pub state: &'a str,
    /// The API transport CSRF handle, rotated on every successful transition.
    pub submit_token: &'a str,
    /// Arbitrary client supplied context, or [`None`]. Serialized JSON stored verbatim in
    /// the `transient_payload` column; NEVER copied onto an identity table.
    pub transient_payload: Option<&'a str>,
    /// The pending LOCAL `/authorize?...` resume target, or [`None`].
    pub return_to: Option<&'a str>,
    /// The flow contract version this row was minted under.
    pub contract_version: i32,
    /// The pinned custom-journey version this flow was created against (issue #92, PR 4), or
    /// [`None`] for a built-in journey. A custom flow re-resolves the SAME compiled table across
    /// submissions from this pin; a built-in flow carries no pin.
    pub flow_version_id: Option<&'a str>,
    /// The row expiry in microseconds since the epoch (from the clock seam).
    pub expires_at_unix_micros: i64,
}

/// A loaded flow row (issue #84): everything a render or a transition needs. Returned by
/// the scope forced load, so a row minted in another scope is a uniform not found.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// The rendered `flw_` id.
    pub id: String,
    /// The journey this row drives.
    pub journey: String,
    /// The transport this flow was created on (immutable).
    pub transport: String,
    /// The serialized state machine position (opaque application JSON).
    pub state: String,
    /// The current API transport CSRF handle.
    pub submit_token: String,
    /// The carried client context, or [`None`].
    pub transient_payload: Option<String>,
    /// The pending LOCAL `/authorize?...` resume target, or [`None`].
    pub return_to: Option<String>,
    /// The flow contract version this row was minted under.
    pub contract_version: i32,
    /// The pinned custom-journey version this flow was created against (issue #92, PR 4), or
    /// [`None`] for a built-in journey.
    pub flow_version_id: Option<String>,
    /// The single use completion instant in microseconds since the epoch, or [`None`]
    /// while the flow is still open.
    pub consumed_at_unix_micros: Option<i64>,
    /// The row expiry in microseconds since the epoch.
    pub expires_at_unix_micros: i64,
}

impl FlowRecord {
    /// Whether this row is still open at `now_unix_micros`: not yet completed (the single
    /// use latch is unset) and not yet expired. A closed row must never re run a
    /// transition; the caller maps the two closed cases to distinct typed flow errors.
    #[must_use]
    pub fn is_expired(&self, now_unix_micros: i64) -> bool {
        self.expires_at_unix_micros <= now_unix_micros
    }

    /// Whether the single use completion latch has tripped.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.consumed_at_unix_micros.is_some()
    }
}
