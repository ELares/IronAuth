// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mapping a SCIM user resource onto IronAuth's identity model (issue #135, criterion 6).
//!
//! The criterion is that a SCIM-created identifier is canonicalized IDENTICALLY to an
//! admin-API-created one, and that duplicate detection proves it. Two provisioning systems
//! writing the same person through different doors must collide, or an operator ends up with
//! two accounts for one human and no way to tell which is real.
//!
//! "Identically" is made structural rather than promised, the same way the filter's is.
//! [`ScimUser::canonical_identifier`] returns a [`CanonicalIdentifier`], which
//! `ironauth-store` documents as producible ONLY by `canonicalize_identifier`. This module
//! therefore cannot invent its own normalization even by accident: to return the type at all
//! it has to call the one function, so "the same rules" is a fact about the call graph rather
//! than a claim in a comment that a later edit could quietly falsify.

use ironauth_store::identifier::{CanonicalIdentifier, IdentifierType, canonicalize_identifier};
use serde::Deserialize;

/// A SCIM 2.0 core user resource, as far as identity mapping reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct ScimUser {
    /// The SCIM `userName`: the login handle.
    #[serde(rename = "userName")]
    pub user_name: String,
    /// The provisioning system's own identifier for this person.
    #[serde(rename = "externalId", default)]
    pub external_id: Option<String>,
    /// Whether the account is enabled.
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

impl ScimUser {
    /// The canonical identifier this resource maps to.
    ///
    /// The TYPE is chosen by shape, not asserted by the caller: a `userName` containing an
    /// `@` is an email and folds its domain too, and anything else is a username. SCIM does
    /// not carry an identifier type, so a mapping that guessed wrong here would canonicalize
    /// one person's handle two different ways depending on which door they arrived through,
    /// which is the exact failure criterion 6 names.
    ///
    /// Deliberately NOT a phone: SCIM carries phone numbers in `phoneNumbers`, never in
    /// `userName`, so treating a numeric handle as one would fold a legitimate username into
    /// E.164 and lose it.
    #[must_use]
    pub fn canonical_identifier(&self) -> CanonicalIdentifier {
        let kind = if self.user_name.contains('@') {
            IdentifierType::Email
        } else {
            IdentifierType::Username
        };
        canonicalize_identifier(kind, &self.user_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scim(user_name: &str) -> ScimUser {
        ScimUser {
            user_name: user_name.to_owned(),
            external_id: None,
            active: true,
        }
    }

    #[test]
    fn a_scim_user_name_canonicalizes_exactly_as_the_admin_api_path_does() {
        // The criterion, asserted directly: the SCIM mapping and a direct call to the shared
        // canonicalizer agree. They cannot disagree by construction, because the mapping HAS
        // to call it to return the type, and this pins the type choice as well.
        for handle in [
            "Alice@Example.COM",
            "alice",
            "ALICE",
            "ad min",
            "Ada.Lovelace@Example.test",
        ] {
            let kind = if handle.contains('@') {
                IdentifierType::Email
            } else {
                IdentifierType::Username
            };
            assert_eq!(
                scim(handle).canonical_identifier(),
                canonicalize_identifier(kind, handle),
                "{handle}"
            );
        }
    }

    #[test]
    fn duplicate_detection_proves_it_for_the_cases_two_doors_actually_differ_on() {
        // What a provisioning system sends and what an operator types differ in exactly these
        // ways: case, surrounding and interior whitespace, and Unicode form. Each pair is ONE
        // person, and a mapping that canonicalized differently would create two accounts.
        let pairs = [
            ("Alice@Example.COM", "alice@example.com"),
            ("  alice  ", "alice"),
            ("ad min", "admin"),
            // NFKC: the fullwidth form a directory export can carry folds onto ASCII.
            ("\u{ff21}LICE", "alice"),
            // A zero-width joiner is invisible and must not make a second account.
            ("ali\u{200d}ce", "alice"),
        ];
        for (left, right) in pairs {
            assert_eq!(
                scim(left).canonical_identifier(),
                scim(right).canonical_identifier(),
                "{left:?} and {right:?} are one person"
            );
        }
    }

    #[test]
    fn genuinely_different_handles_stay_different() {
        // The control. Without it the test above passes on a canonicalizer that mapped
        // everything to the empty string, which would collide every account in the tenant
        // into one and satisfy "duplicate detection" perfectly.
        let distinct = ["alice", "bob", "alice@example.com", "alice@example.test"];
        for (index, left) in distinct.iter().enumerate() {
            for right in &distinct[index + 1..] {
                assert_ne!(
                    scim(left).canonical_identifier(),
                    scim(right).canonical_identifier(),
                    "{left:?} and {right:?} are different people"
                );
            }
        }
    }

    #[test]
    fn an_absent_active_defaults_to_enabled() {
        // SCIM omits `active` for an enabled user, and a mapping that defaulted it to false
        // would deactivate every account a provisioning system created.
        let parsed: ScimUser =
            serde_json::from_str(r#"{"userName":"alice"}"#).expect("a minimal resource");
        assert!(parsed.active);
    }
}
