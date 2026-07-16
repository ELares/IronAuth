// SPDX-License-Identifier: MIT OR Apache-2.0

//! The gap-report model shared by every importer (issue #57).
//!
//! A migration front-end is only trustworthy if it is honest about what it could
//! NOT bring across. Every importer in this crate maps a vendor export into a
//! [`Mapping`]: a per-user list of outcomes where each user either produced an
//! [`ImportRecord`] (possibly with gaps) or was dropped entirely (with a reason).
//! No source field is ever silently discarded: a construct the importer does not
//! carry forward is recorded as a [`Gap`] naming WHAT was skipped and WHY.
//!
//! # Validation-only vs commit
//!
//! Mapping is a pure, database-free transform. A caller runs the
//! VALIDATION-ONLY pass by mapping the export and calling [`Mapping::gap_report`]:
//! it produces the complete field-level gap report WITHOUT creating a single user.
//! The COMMIT pass calls [`Mapping::record_lines`] and feeds those lines to the
//! #55 streaming engine (`ironauth_import::import_stream`). The importer library
//! itself never touches the store, so the two passes cannot diverge.

use ironauth_import::{ImportRecord, to_record_line};

/// The vendor a [`Mapping`] came from, for the gap-report header and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A Keycloak realm export (`realm.json`).
    Keycloak,
    /// An Auth0 bulk user export plus the separate password-hash export.
    Auth0,
    /// A Firebase `auth:export`.
    Firebase,
    /// A generic SCIM 2.0 core user resource set (RFC 7643).
    Scim,
    /// A generic LDAP directory projection with LDAP password schemes.
    Ldap,
}

impl Source {
    /// The stable, human-readable label used in the gap-report header and metrics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Source::Keycloak => "keycloak",
            Source::Auth0 => "auth0",
            Source::Firebase => "firebase",
            Source::Scim => "scim",
            Source::Ldap => "ldap",
        }
    }
}

/// One construct the importer could not carry forward (issue #57): a field-level
/// record of WHAT was skipped and WHY. Never carries a secret value (never a
/// password and never a decoded hash operand); the `construct` is a non-secret
/// label or class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The source field path the construct came from, for example
    /// `credentials[0].algorithm`, `realmRoles`, or `app_metadata.plan`.
    pub field: String,
    /// A short, non-secret description of what was skipped (a value class or label,
    /// never a decoded secret).
    pub construct: String,
    /// Why the construct could not be mapped to an IronAuth target.
    pub reason: String,
}

impl Gap {
    /// Build a gap from three string-like parts.
    pub(crate) fn new(
        field: impl Into<String>,
        construct: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            construct: construct.into(),
            reason: reason.into(),
        }
    }
}

/// What became of a single source user during mapping.
///
/// Not `PartialEq`: it holds an [`ImportRecord`], which the #55 crate does not make
/// comparable; tests match on the variant instead.
#[derive(Debug, Clone)]
pub enum MapOutcome {
    /// The user mapped to an import record (which may still carry gaps for the
    /// fields that were not represented). Boxed to keep the enum small.
    Mapped(Box<ImportRecord>),
    /// The user could not be mapped at all and produces NO record; the string is the
    /// operator-safe reason (for example a missing login handle).
    Dropped(String),
}

/// One source user's mapping outcome plus every gap recorded against it (issue
/// #57).
#[derive(Debug, Clone)]
pub struct MappedUser {
    /// The stable, non-secret source identity the outcome is reported against (the
    /// vendor user id or, when absent, the login handle or a positional placeholder).
    pub source_key: String,
    /// Whether the user mapped to a record or was dropped.
    pub outcome: MapOutcome,
    /// Every field-level gap recorded for this user.
    pub gaps: Vec<Gap>,
}

impl MappedUser {
    /// A user that mapped to a record (possibly with gaps).
    pub(crate) fn mapped(source_key: String, record: ImportRecord, gaps: Vec<Gap>) -> Self {
        Self {
            source_key,
            outcome: MapOutcome::Mapped(Box::new(record)),
            gaps,
        }
    }

    /// A user that could not be mapped at all (dropped, with a reason).
    pub(crate) fn dropped(source_key: String, reason: impl Into<String>, gaps: Vec<Gap>) -> Self {
        Self {
            source_key,
            outcome: MapOutcome::Dropped(reason.into()),
            gaps,
        }
    }

    /// Whether this user was dropped (produced no import record).
    #[must_use]
    pub fn is_dropped(&self) -> bool {
        matches!(self.outcome, MapOutcome::Dropped(_))
    }
}

/// The full result of mapping one vendor export (issue #57): the source and every
/// user's outcome. Database-free; the same value drives both the validation-only
/// pass ([`Mapping::gap_report`]) and the commit pass ([`Mapping::record_lines`]).
#[derive(Debug, Clone)]
pub struct Mapping {
    /// The vendor this mapping came from.
    pub source: Source,
    /// Every source user's outcome, in export order (a deterministic ordering, so
    /// the gap report and record stream are reproducible).
    pub users: Vec<MappedUser>,
}

impl Mapping {
    /// The import record lines to feed the #55 streaming engine: one line per user
    /// that mapped to a record (dropped users contribute none). Feed the result to
    /// `ironauth_import::import_stream`.
    ///
    /// # Errors
    ///
    /// [`serde_json::Error`] only if a mapped record cannot be serialized, which for
    /// the concrete record shape does not occur in practice; it is surfaced rather
    /// than unwrapped so the commit path stays panic-free.
    pub fn record_lines(&self) -> Result<Vec<String>, serde_json::Error> {
        let mut lines = Vec::new();
        for user in &self.users {
            if let MapOutcome::Mapped(record) = &user.outcome {
                lines.push(to_record_line(record)?);
            }
        }
        Ok(lines)
    }

    /// The number of users that mapped to an import record.
    #[must_use]
    pub fn mapped_count(&self) -> usize {
        self.users.iter().filter(|u| !u.is_dropped()).count()
    }

    /// The number of users that were dropped (produced no record).
    #[must_use]
    pub fn dropped_count(&self) -> usize {
        self.users.iter().filter(|u| u.is_dropped()).count()
    }

    /// The complete gap report over this mapping (the validation-only pass output):
    /// every dropped user and every user with at least one gap, with field-level
    /// detail. Producing it creates NO user.
    #[must_use]
    pub fn gap_report(&self) -> GapReport {
        let entries = self
            .users
            .iter()
            .filter_map(|user| {
                let dropped = match &user.outcome {
                    MapOutcome::Dropped(reason) => Some(reason.clone()),
                    MapOutcome::Mapped(_) => None,
                };
                if dropped.is_none() && user.gaps.is_empty() {
                    return None;
                }
                Some(GapEntry {
                    source_key: user.source_key.clone(),
                    dropped,
                    gaps: user.gaps.clone(),
                })
            })
            .collect();
        GapReport {
            source: self.source,
            total: self.users.len(),
            mapped: self.mapped_count(),
            dropped: self.dropped_count(),
            entries,
        }
    }
}

/// One user's contribution to a [`GapReport`]: it is present only when the user was
/// dropped or carries at least one gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapEntry {
    /// The source identity the gaps are reported against.
    pub source_key: String,
    /// The drop reason when the whole record was dropped, else [`None`].
    pub dropped: Option<String>,
    /// The field-level gaps recorded for this user.
    pub gaps: Vec<Gap>,
}

/// The validation-only gap report over a whole export (issue #57): the per-source
/// tally plus one [`GapEntry`] for every user that was dropped or carries a gap.
/// [`GapReport::render`] gives the deterministic text used for the snapshot tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReport {
    /// The vendor the report is for.
    pub source: Source,
    /// The total number of source users seen.
    pub total: usize,
    /// The number that mapped to an import record.
    pub mapped: usize,
    /// The number that were dropped.
    pub dropped: usize,
    /// One entry per dropped user and per user carrying a gap, in export order.
    pub entries: Vec<GapEntry>,
}

impl GapReport {
    /// Whether the report is clean: no dropped users and no gaps. A clean report
    /// means the export mapped losslessly.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }

    /// The total number of individual gaps across every user (excludes drops).
    #[must_use]
    pub fn gap_count(&self) -> usize {
        self.entries.iter().map(|e| e.gaps.len()).sum()
    }

    /// Render the report as deterministic, human-readable text: a header line, the
    /// tally, then each entry with its drop reason (if any) and its gaps. Stable
    /// across runs (export order, no timestamps), so it drives the snapshot tests.
    #[must_use]
    pub fn render(&self) -> String {
        use core::fmt::Write as _;

        let mut out = String::new();
        // Writes to a String are infallible, so the results are discarded.
        let _ = writeln!(out, "{} import gap report", self.source.label());
        let _ = writeln!(
            out,
            "users: {} (mapped {}, dropped {})",
            self.total, self.mapped, self.dropped
        );
        if self.entries.is_empty() {
            out.push_str("no gaps: every field mapped\n");
            return out;
        }
        for entry in &self.entries {
            out.push('\n');
            match &entry.dropped {
                Some(reason) => {
                    let _ = writeln!(out, "[{}] DROPPED: {}", entry.source_key, reason);
                }
                None => {
                    let _ = writeln!(out, "[{}]", entry.source_key);
                }
            }
            for gap in &entry.gaps {
                let _ = writeln!(out, "  - {}: {} ({})", gap.field, gap.construct, gap.reason);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(identifier: &str) -> ImportRecord {
        ImportRecord {
            identifier: identifier.to_owned(),
            id: None,
            external_id: None,
            state: None,
            claims: None,
            traits: None,
            traits_schema_version: None,
            password_hash: None,
            credentials: None,
        }
    }

    #[test]
    fn record_lines_skip_dropped_users() {
        let mapping = Mapping {
            source: Source::Scim,
            users: vec![
                MappedUser::mapped("a".to_owned(), record("a@x.test"), Vec::new()),
                MappedUser::dropped("b".to_owned(), "no login handle", Vec::new()),
                MappedUser::mapped("c".to_owned(), record("c@x.test"), Vec::new()),
            ],
        };
        let lines = mapping.record_lines().expect("serialize");
        assert_eq!(lines.len(), 2, "the dropped user contributes no line");
        assert_eq!(mapping.mapped_count(), 2);
        assert_eq!(mapping.dropped_count(), 1);
    }

    #[test]
    fn a_clean_mapping_reports_no_entries() {
        let mapping = Mapping {
            source: Source::Scim,
            users: vec![MappedUser::mapped(
                "a".to_owned(),
                record("a@x.test"),
                Vec::new(),
            )],
        };
        let report = mapping.gap_report();
        assert!(report.is_clean());
        assert_eq!(report.gap_count(), 0);
        assert!(report.render().contains("no gaps"));
    }

    #[test]
    fn gaps_and_drops_surface_in_the_report() {
        let mapping = Mapping {
            source: Source::Keycloak,
            users: vec![
                MappedUser::mapped(
                    "u1".to_owned(),
                    record("u1@x.test"),
                    vec![Gap::new(
                        "realmRoles",
                        "2 realm roles",
                        "no representable target",
                    )],
                ),
                MappedUser::dropped("u2".to_owned(), "missing username", Vec::new()),
            ],
        };
        let report = mapping.gap_report();
        assert!(!report.is_clean());
        assert_eq!(report.total, 2);
        assert_eq!(report.mapped, 1);
        assert_eq!(report.dropped, 1);
        assert_eq!(report.gap_count(), 1);
        let text = report.render();
        assert!(text.contains("[u1]"));
        assert!(text.contains("realmRoles"));
        assert!(text.contains("[u2] DROPPED: missing username"));
    }
}
