// SPDX-License-Identifier: MIT OR Apache-2.0

//! Subject-bound recipient verification (issue #1436).
//!
//! This is separate from login OTPs. Verification records mailbox ownership and
//! never creates a session or changes authentication strength. Ordinary password
//! signup can verify its own email-shaped primary identifier. Additional mailbox
//! enrollment and legacy-index backfill are deliberately not inferred here.

use crate::{RecipientChallengeId, UserId, UserIdentifierId};

/// A bounded inspection or backfill report. Counts describe the scoped snapshot;
/// no address, blind index, password, verification code or ownership proof leaves
/// the repository through this type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecipientIndexReport {
    /// Whether this call committed the inspected batch's index metadata.
    pub applied: bool,
    /// Retained users decoded in this batch, at most the requested bound.
    pub batch_users: u32,
    /// Batch users with a nonempty canonical mailbox ownership reservation.
    pub batch_mailbox_users: u32,
    /// Retained users in the exact tenant/environment, including deleted users.
    pub total_users: i64,
    /// Users whose primary-identifier index has not been established yet.
    pub unindexed_users: i64,
    /// Conflicting canonical ownership groups among currently indexed primary
    /// and typed identifiers. Incomplete indexing can still reveal more groups.
    pub ambiguous_indexed_mailboxes: i64,
    /// True only when every retained primary identifier has been indexed.
    /// This does not assert that every user has a deliverable or verified email.
    pub index_complete: bool,
}

/// A challenge issued to an already authenticated subject.
pub struct NewRecipientChallenge<'a> {
    /// Fresh scope-bound challenge handle.
    pub id: &'a RecipientChallengeId,
    /// The authenticated subject, never a browser-supplied identity.
    pub subject: &'a UserId,
    /// The mailbox the subject is proving.
    pub email: &'a str,
    /// One-way Argon2id verifier. Never a plaintext code.
    pub code_hash: &'a str,
    /// Expiry from the environment clock, at most ten minutes after issuance.
    pub expires_at_unix_micros: i64,
}

/// Private verification input resolved for this subject and challenge.
///
/// The verifier is intentionally omitted from `Debug` and from every wire type.
pub struct RecipientChallenge {
    /// Challenge identity, also the optimistic verification revision.
    pub id: RecipientChallengeId,
    /// One-way verifier to check through the admission-controlled hashing pool.
    pub code_hash: String,
}

/// The committed result of one verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientAttempt {
    /// The challenge was wrong or its attempts were exhausted. No ownership changed.
    Refused,
    /// Challenge consumption, ownership and audit committed together.
    Verified,
}

/// Current store-owned proof inputs. A transport adds its verified issuer/client,
/// public subject and nonce, never labels or arbitrary stored OIDC claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecipient {
    /// The current verified identifier row; removal/replacement invalidates proof.
    pub identifier_id: UserIdentifierId,
    /// The exact successful challenge, a fresh epoch for each verification.
    pub revision: RecipientChallengeId,
    /// When ownership was verified, from the environment clock.
    pub verified_at_unix_micros: i64,
}

/// Secret-bearing mailbox requests must be bounded and cannot contain header
/// controls. Identity equality still uses the one identifier canonicalizer.
#[must_use]
pub fn valid_recipient_email(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 254
        && value.trim() == value
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        && value.split('@').count() == 2
        && !crate::identifier::canonicalize_identifier(crate::IdentifierType::Email, value)
            .is_empty()
}

#[cfg(test)]
mod tests {
    use super::valid_recipient_email;

    #[test]
    fn delivery_input_refuses_controls_and_non_mailbox_shapes() {
        for value in [
            "",
            "account",
            "a@@b.test",
            "a@",
            "@b.test",
            " a@b.test",
            "a@b.test\r\nBcc:c@d.test",
            "a\u{2028}@b.test",
        ] {
            assert!(!valid_recipient_email(value), "{value:?}");
        }
        assert!(valid_recipient_email("Owner@Example.test"));
        assert!(valid_recipient_email("Ｏwner@example.test"));
    }
}
