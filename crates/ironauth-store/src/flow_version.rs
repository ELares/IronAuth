// SPDX-License-Identifier: MIT OR Apache-2.0

//! The custom-journey version registry value types and the load-time write validation (issue #92,
//! PR 5).
//!
//! A custom (declarative) journey is authored as a canonical [`ironauth_journey::Journey`]
//! artifact and stored as an immutable, append-only VERSION: one row per (tenant, environment,
//! `journey_id`, version). A per-journey PIN names the active version a fresh custom flow is created
//! against. This module holds only the PURE value logic (no SQL, no clock, no entropy): the typed
//! records the persistence surface reads back, the parameters a create takes, and the fail-fast
//! write validation that refuses an artifact BEFORE it is stored unless it is a load-valid,
//! compilable journey. The scoped repositories (read and acting) live in the repository module and
//! consume these types.
//!
//! ## The write-time gate
//!
//! [`validate_artifact_json`] is the single load-time gate. A stored artifact is always already a
//! compilable journey, so the engine's [`ironauth_journey::compile`] on the read path never fails
//! on a stored version. Compilation composes (validating the source, its subflow references, and
//! its acyclicity), inlines every subflow, re-validates the flattened result, and checks a
//! reachable completion exists, so it SUBSUMES a standalone validate pass. A journey artifact
//! carries NO secret by construction: a predicate references trait POINTERS and group / scope
//! NAMES, never values.

use ironauth_journey::{Journey, JourneyError};

/// A custom-journey version to create (issue #92, PR 5). The `artifact_json` is the canonical
/// journey document; it is validated load-valid ([`validate_artifact_json`]) before the store
/// writes it, so a stored version is always already compilable.
#[derive(Debug, Clone, Copy)]
pub struct NewFlowVersion<'a> {
    /// The author-facing journey id this version belongs to (stable across the journey's
    /// versions), the per-scope natural key together with the version number.
    pub journey_id: &'a str,
    /// The canonical journey artifact (a JSON document), stored verbatim as `jsonb` once validated.
    pub artifact_json: &'a str,
}

/// A stored custom-journey version, read back (issue #92, PR 5). The `artifact_json` is the
/// canonical journey document exactly as validated on write, and `pinned` reports whether this
/// version is the journey's active pin in the scope (populated by the read that joins the pin
/// table, absent-as-`false` otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowVersionRecord {
    /// The `flv_` version id (embeds its scope).
    pub id: String,
    /// The author-facing journey id this version belongs to.
    pub journey_id: String,
    /// The per-scope, per-journey_id monotonic version number.
    pub version: i32,
    /// The canonical journey artifact (a JSON document).
    pub artifact_json: String,
    /// Whether this version is the journey's active pin in the scope.
    pub pinned: bool,
}

/// Fail-fast validate a custom-journey artifact BEFORE it is stored (issue #92, PR 5): the
/// write-time gate. The store keeps only a version that passes.
///
/// The artifact must parse as a [`ironauth_journey::Journey`] and then COMPILE
/// ([`ironauth_journey::compile`], which composes, validates the source and its references,
/// re-validates the flattened result, and checks a reachable completion), so a stored version is
/// always already a load-valid, live journey. Each returned [`JourneyError`] is operator-safe and
/// value-free (an RFC 6901 pointer and a stable reason), so a rejection carries no secret and no
/// caller instance data.
///
/// # Errors
///
/// The `Vec<JourneyError>` of every load-time failure (an EMPTY vec when the document does not even
/// parse as a journey, which the management surface reports as a malformed document before this
/// gate is reached).
pub fn validate_artifact_json(artifact_json: &str) -> Result<(), Vec<JourneyError>> {
    let journey: Journey = serde_json::from_str(artifact_json).map_err(|_| Vec::new())?;
    validate_artifact(&journey)
}

/// Fail-fast validate an already-parsed custom-journey artifact (issue #92, PR 5): the same
/// load-time gate as [`validate_artifact_json`], for a caller that already holds the parsed
/// [`Journey`] (the management surface, which parses once and reuses the value).
///
/// # Errors
///
/// The `Vec<JourneyError>` of every load-time failure.
pub fn validate_artifact(journey: &Journey) -> Result<(), Vec<JourneyError>> {
    ironauth_journey::compile(journey).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{FlowVersionRecord, validate_artifact_json};

    /// A minimal load-valid journey: a single identifier/password step routing to a terminal.
    fn valid_artifact() -> String {
        serde_json::json!({
            "schema_version": "ironauth.journey/v1",
            "id": "login_basic",
            "engine_version": 1,
            "entry": "primary",
            "steps": [
                {"id": "primary", "kind": "identifier_password"},
                {"id": "done", "kind": "terminal"}
            ],
            "transitions": [
                {"from": "primary", "to": "done"}
            ]
        })
        .to_string()
    }

    #[test]
    fn a_load_valid_artifact_passes_the_write_gate() {
        assert_eq!(validate_artifact_json(&valid_artifact()), Ok(()));
    }

    #[test]
    fn a_dangling_transition_is_rejected_with_errors() {
        // A transition to an undeclared step is a load-time fault: compile refuses it.
        let doc = serde_json::json!({
            "schema_version": "ironauth.journey/v1",
            "id": "broken",
            "engine_version": 1,
            "entry": "primary",
            "steps": [
                {"id": "primary", "kind": "identifier_password"},
                {"id": "done", "kind": "terminal"}
            ],
            "transitions": [
                {"from": "primary", "to": "nowhere"}
            ]
        })
        .to_string();
        let errors = validate_artifact_json(&doc).expect_err("a dangling transition is rejected");
        assert!(
            !errors.is_empty(),
            "the rejection names the load-time errors"
        );
    }

    #[test]
    fn a_non_journey_document_is_rejected() {
        // A document that does not parse as a journey yields the empty-error rejection (the
        // management surface reports the malformed document precisely before this gate).
        assert_eq!(
            validate_artifact_json("{\"not\":\"a journey\"}"),
            Err(Vec::new())
        );
        assert_eq!(validate_artifact_json("not json at all"), Err(Vec::new()));
    }

    #[test]
    fn a_record_round_trips_its_fields() {
        let record = FlowVersionRecord {
            id: "flv_example".to_owned(),
            journey_id: "login_basic".to_owned(),
            version: 2,
            artifact_json: valid_artifact(),
            pinned: true,
        };
        assert_eq!(record.version, 2);
        assert!(record.pinned);
    }
}
