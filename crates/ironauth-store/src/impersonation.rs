// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audited impersonation value type (issue #101).
//!
//! Migration 0128 makes an unjustified or over-cap impersonation session unstorable. This is
//! the same rule stated a second time, in the type system, and the duplication is deliberate:
//! the CHECK is what holds against every writer that will ever exist, and this is what gives
//! the writer a TYPED refusal naming which rule it broke instead of a constraint violation
//! that surfaces as an opaque database error.
//!
//! [`Impersonation`] has private fields and one constructor. A caller cannot assemble an
//! impersonation that skipped validation, which is the same property the arc CHECK gives the
//! table, so the two cannot disagree about what a justified session is.

/// The hard cap on an impersonation session, in microseconds (issue #101).
///
/// Sixty minutes, and NOT configurable. The criterion calls it "a hard bound, not configurable
/// upward", so it is a constant rather than a setting: a knob is exactly the thing an operator
/// under pressure turns up, and the same bound is written into 0128 so a value that got past
/// this constant still could not be stored.
pub const IMPERSONATION_MAX_DURATION_MICROS: i64 = 60 * 60 * 1_000_000;

/// Why an impersonation request was refused (issue #101).
///
/// One variant per rule, rather than a single "invalid", because the criterion asks for a
/// typed error and because an operator told only "rejected" retries the same request. Each
/// carries a stable wire code and no tenant data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationRejection {
    /// No impersonator was named, or the name was blank.
    MissingImpersonator,
    /// The structured reason was absent or blank.
    MissingReasonCode,
    /// The free-text justification was absent or blank. Distinct from a missing code: an
    /// operator who supplied a category and no sentence has answered "what kind" and not
    /// "why this user, right now", which is what an auditor reads.
    MissingReasonText,
    /// The requested duration exceeds [`IMPERSONATION_MAX_DURATION_MICROS`].
    CapExceeded,
    /// The requested duration was zero or negative, which is not a session.
    NotAfterStart,
}

impl ImpersonationRejection {
    /// A stable code for the wire, safe to log and to show an operator.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingImpersonator => "impersonator_required",
            Self::MissingReasonCode => "reason_code_required",
            Self::MissingReasonText => "reason_text_required",
            Self::CapExceeded => "impersonation_cap_exceeded",
            Self::NotAfterStart => "impersonation_duration_invalid",
        }
    }

    /// An operator-facing sentence. Carries no tenant data.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::MissingImpersonator => "impersonation requires the impersonating principal",
            Self::MissingReasonCode => {
                "impersonation requires a structured reason code; requests without one are \
                 rejected"
            }
            Self::MissingReasonText => {
                "impersonation requires a written justification alongside the reason code; a \
                 category alone is not a justification"
            }
            Self::CapExceeded => {
                "an impersonation session may last at most 60 minutes, and the cap is not \
                 configurable upward"
            }
            Self::NotAfterStart => "an impersonation session must end after it starts",
        }
    }
}

/// A validated impersonation, ready to be attached to a session (issue #101).
///
/// Constructed only through [`Impersonation::start`], so every value of this type has already
/// satisfied every rule 0128 enforces. The fields are private for that reason: a public field
/// would let a caller build one field at a time and reach the database with a row the CHECK
/// then refuses, which turns a typed refusal into a 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Impersonation<'a> {
    impersonator: &'a str,
    reason_code: &'a str,
    reason_text: &'a str,
    started_at_unix_micros: i64,
    expires_at_unix_micros: i64,
}

impl<'a> Impersonation<'a> {
    /// Validate an impersonation request and answer the value a session can carry.
    ///
    /// `requested_duration_micros` is what the caller ASKED for. It is refused rather than
    /// clamped when it exceeds the cap: the criterion says extension past the cap FAILS, and
    /// silently shortening a request tells an operator their sixty-first minute was granted.
    ///
    /// # Errors
    ///
    /// [`ImpersonationRejection`], one variant per rule, so a caller can say which.
    pub fn start(
        impersonator: &'a str,
        reason_code: &'a str,
        reason_text: &'a str,
        started_at_unix_micros: i64,
        requested_duration_micros: i64,
    ) -> Result<Self, ImpersonationRejection> {
        if impersonator.trim().is_empty() {
            return Err(ImpersonationRejection::MissingImpersonator);
        }
        if reason_code.trim().is_empty() {
            return Err(ImpersonationRejection::MissingReasonCode);
        }
        if reason_text.trim().is_empty() {
            return Err(ImpersonationRejection::MissingReasonText);
        }
        if requested_duration_micros <= 0 {
            return Err(ImpersonationRejection::NotAfterStart);
        }
        if requested_duration_micros > IMPERSONATION_MAX_DURATION_MICROS {
            return Err(ImpersonationRejection::CapExceeded);
        }
        Ok(Self {
            impersonator,
            reason_code,
            reason_text,
            started_at_unix_micros,
            // Checked, not saturating: an overflow here would wrap to a time before the start
            // and 0128 would refuse the row, so answering the cap rejection is both the safe
            // result and the true one.
            expires_at_unix_micros: started_at_unix_micros
                .checked_add(requested_duration_micros)
                .ok_or(ImpersonationRejection::CapExceeded)?,
        })
    }

    /// The impersonating principal, as recorded on the session and in the `act` claim.
    #[must_use]
    pub const fn impersonator(&self) -> &'a str {
        self.impersonator
    }

    /// The structured reason.
    #[must_use]
    pub const fn reason_code(&self) -> &'a str {
        self.reason_code
    }

    /// The written justification.
    #[must_use]
    pub const fn reason_text(&self) -> &'a str {
        self.reason_text
    }

    /// When the impersonation started, in microseconds since the Unix epoch.
    #[must_use]
    pub const fn started_at_unix_micros(&self) -> i64 {
        self.started_at_unix_micros
    }

    /// When it must stop, in microseconds since the Unix epoch. At most the cap past the
    /// start, which 0128 also enforces.
    #[must_use]
    pub const fn expires_at_unix_micros(&self) -> i64 {
        self.expires_at_unix_micros
    }
}

#[cfg(test)]
mod tests {
    use super::{IMPERSONATION_MAX_DURATION_MICROS, Impersonation, ImpersonationRejection};

    const START: i64 = 1_700_000_000_000_000;

    fn start<'a>(
        code: &'a str,
        text: &'a str,
        duration: i64,
    ) -> Result<Impersonation<'a>, ImpersonationRejection> {
        Impersonation::start("adm_support", code, text, START, duration)
    }

    /// Each rule refuses with its OWN variant.
    ///
    /// Driven as a table rather than one assertion per rule, so a constructor that collapsed
    /// every failure into one variant fails here rather than reading as correct.
    #[test]
    fn every_rule_refuses_with_its_own_variant() {
        assert_eq!(
            Impersonation::start("", "code", "text", START, 60),
            Err(ImpersonationRejection::MissingImpersonator)
        );
        assert_eq!(
            start("", "text", 60),
            Err(ImpersonationRejection::MissingReasonCode)
        );
        assert_eq!(
            start("code", "", 60),
            Err(ImpersonationRejection::MissingReasonText)
        );
        assert_eq!(
            start("code", "text", 0),
            Err(ImpersonationRejection::NotAfterStart)
        );
        assert_eq!(
            start("code", "text", -1),
            Err(ImpersonationRejection::NotAfterStart)
        );
        assert_eq!(
            start("code", "text", IMPERSONATION_MAX_DURATION_MICROS + 1),
            Err(ImpersonationRejection::CapExceeded)
        );
    }

    /// Whitespace is not a justification, matching 0128's `btrim` check.
    ///
    /// The two rules are written in different languages against the same requirement, so this
    /// is the assertion that keeps them agreeing. A tab and a newline is the exact value that
    /// slipped past the migration's first attempt.
    #[test]
    fn whitespace_is_not_a_justification() {
        assert_eq!(
            start("   ", "text", 60),
            Err(ImpersonationRejection::MissingReasonCode)
        );
        assert_eq!(
            start("code", "\t\n ", 60),
            Err(ImpersonationRejection::MissingReasonText)
        );
    }

    /// Exactly at the cap is allowed, and the expiry is the start plus the duration.
    ///
    /// The boundary is asserted because a test that only probed over-cap could not tell an
    /// inclusive bound from an exclusive one, and 0128's bound is inclusive.
    #[test]
    fn the_cap_is_inclusive_and_the_expiry_is_derived() {
        let at_cap = start("code", "text", IMPERSONATION_MAX_DURATION_MICROS)
            .expect("exactly at the cap is allowed");
        assert_eq!(at_cap.started_at_unix_micros(), START);
        assert_eq!(
            at_cap.expires_at_unix_micros(),
            START + IMPERSONATION_MAX_DURATION_MICROS
        );
    }

    /// An overflowing start answers the cap rejection rather than wrapping.
    ///
    /// `i64::MAX` as a start time is not reachable from the clock, but a caller computing one
    /// is, and a wrap would put the expiry BEFORE the start, which reaches the database as a
    /// constraint violation instead of a typed refusal.
    #[test]
    fn an_overflowing_start_is_refused_rather_than_wrapped() {
        assert_eq!(
            Impersonation::start("adm", "code", "text", i64::MAX, 60),
            Err(ImpersonationRejection::CapExceeded)
        );
    }
}
