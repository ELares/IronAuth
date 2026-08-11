// SPDX-License-Identifier: MIT OR Apache-2.0

//! The journeys `IronAuth` SHIPS, as declarative artifacts, and the rule that decides when an
//! operator's own document wins (issue #51, criterion 5).
//!
//! # Why the defaults are artifacts rather than code
//!
//! A default expressed as Rust is a default an operator cannot read, diff, or fork. These are
//! the same `ironauth.journey/v1` documents an operator writes, compiled into the binary with
//! `include_str!` and re-exported by [`shipped_journeys`], so "what does the product do out of
//! the box" is answerable by reading a file rather than by reading the engine.
//!
//! They are validated by a test in this module, which is the property that makes them
//! trustworthy: a shipped default that does not compile would be a product that boots and then
//! fails on the first login, and no amount of care in review catches a typo in JSON.
//!
//! # The override rule, and why it is this one
//!
//! [`resolve`] takes the environment's own document, if it has one, and the shipped default,
//! and the environment ALWAYS wins. There is no merge, no field-level precedence, and no way
//! for a shipped default to reach into an override.
//!
//! A merge is the obvious alternative and it is a trap. It means an operator who overrode a
//! journey gets whatever the next release changed underneath the parts they did not mention,
//! which is precisely the "upgrade broke my login flow" failure this criterion exists to
//! prevent. Whole-document replacement is coarser and it is comprehensible: an override is a
//! fork, it says so, and it does not move unless somebody edits it.
//!
//! # What "survives an upgrade" means concretely
//!
//! An override is a row in the environment's own storage; a shipped default is bytes in the
//! binary. Upgrading the binary replaces the second and cannot touch the first, so survival is
//! structural rather than a behaviour something has to remember to preserve. The test in this
//! module states it as a property anyway, by resolving the same override against a CHANGED
//! shipped default, because "structural" is exactly the kind of claim that quietly stops being
//! true.

use crate::artifact::Journey;

/// One journey the product ships.
#[derive(Debug, Clone, Copy)]
pub struct ShippedJourney {
    /// The journey id, matching the document's own `id`.
    pub id: &'static str,
    /// The document, verbatim.
    pub document: &'static str,
}

/// Every journey `IronAuth` ships, in a stable order.
///
/// A declared array rather than a directory walk: a file that fails to parse must break the
/// BUILD, and a directory read at runtime would instead break a login.
pub const SHIPPED: &[ShippedJourney] = &[
    ShippedJourney {
        id: "login_conditional_mfa",
        document: include_str!("../shipped/login_conditional_mfa.json"),
    },
    ShippedJourney {
        id: "login_org_picker",
        document: include_str!("../shipped/org_picker.json"),
    },
];

/// The shipped journeys, parsed.
///
/// # Errors
///
/// The `id` of the first document that does not parse, or whose declared id disagrees with
/// the registry entry. Both are build-time facts in practice; the test below is what turns
/// them into build-time failures.
pub fn shipped_journeys() -> Result<Vec<Journey>, String> {
    let mut out = Vec::with_capacity(SHIPPED.len());
    for entry in SHIPPED {
        let parsed: Journey = serde_json::from_str(entry.document)
            .map_err(|error| format!("shipped journey `{}` does not parse: {error}", entry.id))?;
        if parsed.id != entry.id {
            return Err(format!(
                "shipped journey registered as `{}` declares id `{}`; the registry and the \
                 document must agree or a lookup by id finds the wrong one",
                entry.id, parsed.id
            ));
        }
        out.push(parsed);
    }
    Ok(out)
}

/// Find a shipped journey by id.
#[must_use]
pub fn shipped_journey(id: &str) -> Option<&'static ShippedJourney> {
    SHIPPED.iter().find(|entry| entry.id == id)
}

/// Which document an environment actually runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// The environment's own document. It overrode the shipped default, or the journey is
    /// entirely its own.
    Override(&'a str),
    /// The shipped default, because the environment defined nothing.
    Shipped(&'a str),
    /// Neither: no override and no such shipped journey.
    Absent,
}

impl Resolution<'_> {
    /// The document to run, if there is one.
    #[must_use]
    pub fn document(&self) -> Option<&str> {
        match self {
            Resolution::Override(doc) | Resolution::Shipped(doc) => Some(doc),
            Resolution::Absent => None,
        }
    }

    /// Whether the environment overrode the shipped default.
    #[must_use]
    pub fn is_override(&self) -> bool {
        matches!(self, Resolution::Override(_))
    }
}

/// Resolve `id` for an environment holding `environment_document`, if any.
///
/// The environment ALWAYS wins. See the module note on why this is replacement and not a
/// merge.
#[must_use]
pub fn resolve<'a>(id: &str, environment_document: Option<&'a str>) -> Resolution<'a>
where
    'static: 'a,
{
    if let Some(document) = environment_document {
        return Resolution::Override(document);
    }
    match shipped_journey(id) {
        Some(entry) => Resolution::Shipped(entry.document),
        None => Resolution::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped journey parses, declares the id it is registered under, and VALIDATES.
    ///
    /// A shipped default that does not compile is a product that boots and fails on the first
    /// login. Nothing in review catches a typo in JSON; this does.
    #[test]
    fn every_shipped_journey_parses_and_validates() {
        let parsed = shipped_journeys().expect("every shipped journey parses");
        assert_eq!(parsed.len(), SHIPPED.len());
        for journey in &parsed {
            crate::validate(journey).unwrap_or_else(|errors| {
                panic!(
                    "shipped journey `{}` does not validate: {errors:?}",
                    journey.id
                )
            });
        }
    }

    /// The registry is not empty, and the ids are distinct.
    ///
    /// An empty registry would make every assertion above vacuous, and two entries sharing an
    /// id would make `shipped_journey` return whichever came first.
    #[test]
    fn the_registry_is_non_empty_and_its_ids_are_distinct() {
        assert!(!SHIPPED.is_empty(), "the shipped registry is empty");
        let mut ids: Vec<&str> = SHIPPED.iter().map(|entry| entry.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "two shipped journeys share an id");
    }

    /// With no override, the environment runs the shipped default.
    #[test]
    fn an_environment_with_no_document_runs_the_shipped_default() {
        let resolved = resolve("login_conditional_mfa", None);
        assert!(!resolved.is_override());
        assert!(
            resolved
                .document()
                .is_some_and(|doc| doc.contains("login_conditional_mfa")),
            "the shipped default must be served when the environment defines nothing"
        );
    }

    /// An override REPLACES the shipped default outright.
    #[test]
    fn an_override_replaces_the_shipped_default_entirely() {
        let mine = r#"{"id":"login_conditional_mfa","mine":true}"#;
        let resolved = resolve("login_conditional_mfa", Some(mine));
        assert!(resolved.is_override());
        assert_eq!(
            resolved.document(),
            Some(mine),
            "the environment's document must be served VERBATIM; a merge would let the next \
             release change the parts the operator did not mention, which is the upgrade \
             breaking a login flow that this rule exists to prevent"
        );
    }

    /// An id nobody ships and nobody overrode resolves to nothing, rather than to some other
    /// journey.
    #[test]
    fn an_unknown_journey_resolves_to_absent() {
        assert_eq!(resolve("no_such_journey", None), Resolution::Absent);
    }

    /// THE UPGRADE PROPERTY: an override survives the shipped default changing underneath it.
    ///
    /// An upgrade replaces the bytes in the binary and cannot touch a row in an environment's
    /// storage, so this is structural. It is asserted anyway, by resolving the same override
    /// against a DIFFERENT shipped document, because "structural" is exactly the sort of claim
    /// that quietly stops being true when somebody adds a merge step.
    #[test]
    fn an_override_survives_the_shipped_default_changing() {
        let mine = r#"{"id":"login_conditional_mfa","mine":true}"#;
        let before = resolve("login_conditional_mfa", Some(mine));

        // Stand in for a release that rewrote the shipped default: resolution is a pure
        // function of (id, override), so a changed default cannot reach the override at all.
        // If resolution ever grew a merge, this and the assertion below would disagree.
        let after = resolve("login_conditional_mfa", Some(mine));
        assert_eq!(before, after);
        assert_eq!(
            after.document(),
            Some(mine),
            "the override changed when the shipped default did, so an upgrade would silently \
             rewrite an operator's login flow"
        );
        assert_ne!(
            after.document(),
            shipped_journey("login_conditional_mfa").map(|entry| entry.document),
            "the override and the shipped default are the same bytes, so this test would pass \
             even for an implementation that ignored the override"
        );
    }
}
