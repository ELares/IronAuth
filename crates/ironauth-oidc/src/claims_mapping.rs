// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declarative claims mapping (issue #113, acceptance criteria 4 and 5).
//!
//! > Declarative mappings cover renames, group filtering, static claims, and ID-versus-access-
//! > token placement with NO CUSTOM CODE.
//!
//! Four operations, configured as data. The point of the criterion is the "no custom code": an
//! operator who wants `groups` renamed to `roles` in the access token should not need a hook, a
//! WASM module, or a CEL expression. Those exist for the cases this cannot express; this exists
//! so they are not needed for the cases it can.
//!
//! # Protected claims are refused, not dropped
//!
//! Criterion 5: `iss`, `sub`, `aud`, `exp` and `iat` "cannot be overridden by any mapping or
//! hook; attempts are rejected and audited".
//!
//! REJECTED, which is stronger than ignored and deliberately so. A mapping that silently
//! dropped a rule targeting `sub` would leave an operator believing they had rewritten the
//! subject, and the first they would learn otherwise is a downstream system reading a `sub`
//! they did not expect. A typed refusal names the rule and the claim, so the configuration is
//! wrong at the moment it is written rather than quietly inert forever.
//!
//! The AUDIT half belongs to the caller: this module is pure and writes nothing. It returns
//! which rule was refused and why, so the caller has something specific to record.
//!
//! # What order means here
//!
//! Rules apply in the order given, and that is observable: a rename followed by a static claim
//! of the same name behaves differently from the reverse. Rather than declare one ordering
//! canonical and hide it, the sequence is the operator's and this applies it as written.

use std::collections::BTreeMap;

use crate::scope_claims::is_protected_claim;

/// Which token a claim is written into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// The ID token only. Identity for the client's own use.
    IdToken,
    /// The access token only. Authorization data for a resource server, which should not need
    /// the whole identity to make a decision.
    AccessToken,
    /// Both, which is the default for a claim no rule places.
    Both,
}

/// One declarative operation.
#[derive(Debug, Clone, PartialEq)]
pub enum MappingRule {
    /// Rename a claim. The source is removed and its value written under the new name.
    Rename {
        /// The claim to take the value from.
        from: String,
        /// The name to write it under.
        to: String,
    },
    /// Write a constant. Overwrites whatever a previous rule left under the name.
    Static {
        /// The claim to write.
        name: String,
        /// The value, as parsed JSON so an operator can configure an object or a list.
        value: serde_json::Value,
    },
    /// Keep only the listed members of a claim whose value is a list of strings.
    ///
    /// The common case is group filtering: an environment with three thousand groups should not
    /// put all of them in every token, and which ones matter is per-client configuration rather
    /// than code.
    FilterList {
        /// The claim to filter.
        name: String,
        /// The members to keep. A member not present in the value is not an error: the rule
        /// says what may pass, not what must be there.
        allow: Vec<String>,
    },
    /// Place a claim in one token or both.
    Place {
        /// The claim to place.
        name: String,
        /// Where it goes.
        placement: Placement,
    },
}

impl MappingRule {
    /// The claim this rule WRITES, which is the one a protected-claim check must look at.
    ///
    /// A `Rename` writes its destination: reading `sub` and writing `subject` is allowed, and
    /// it is writing INTO `sub` that is refused. Getting this backwards would forbid the safe
    /// direction and permit the unsafe one.
    fn written_claim(&self) -> &str {
        match self {
            Self::Rename { to, .. } => to,
            Self::Static { name, .. }
            | Self::FilterList { name, .. }
            | Self::Place { name, .. } => name,
        }
    }
}

/// Why a mapping was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRefusal {
    /// Which rule, by position, so an operator can find it in a list of forty.
    pub rule_index: usize,
    /// The protected claim it tried to write.
    pub claim: String,
}

impl core::fmt::Display for MappingRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "rule {} writes the protected claim `{}`, which no mapping may set",
            self.rule_index, self.claim
        )
    }
}

impl std::error::Error for MappingRefusal {}

/// The claims a mapping produced, split by the token they belong in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MappedClaims {
    /// Claims for the ID token.
    pub id_token: BTreeMap<String, serde_json::Value>,
    /// Claims for the access token.
    pub access_token: BTreeMap<String, serde_json::Value>,
}

/// Check a mapping without applying it.
///
/// Separate from [`apply`] because configuration should be refused when it is WRITTEN, not on
/// the first token issued from it. A caller that validates on write turns a protected-claim
/// mistake into an error the operator sees immediately; one that only validates at issuance
/// turns it into a failed login at an unpredictable time.
///
/// # Errors
///
/// [`MappingRefusal`] naming the first rule that writes a protected claim.
pub fn validate(rules: &[MappingRule]) -> Result<(), MappingRefusal> {
    for (index, rule) in rules.iter().enumerate() {
        let written = rule.written_claim();
        if is_protected_claim(written) {
            return Err(MappingRefusal {
                rule_index: index,
                claim: written.to_owned(),
            });
        }
    }
    Ok(())
}

/// Apply `rules` to `source`, producing the per-token claim sets.
///
/// Validates first, so an unvalidated mapping cannot half-apply: a refusal leaves the caller
/// with no claims rather than with the claims the rules before the bad one produced.
///
/// # Errors
///
/// [`MappingRefusal`], exactly as [`validate`].
pub fn apply(
    rules: &[MappingRule],
    source: &BTreeMap<String, serde_json::Value>,
) -> Result<MappedClaims, MappingRefusal> {
    validate(rules)?;

    let mut working = source.clone();
    // Placement is decided per claim, and a claim nothing places goes in BOTH: that is the
    // behaviour before any mapping existed, so a mapping that says nothing about a claim does
    // not move it.
    let mut placements: BTreeMap<String, Placement> = BTreeMap::new();

    for rule in rules {
        match rule {
            MappingRule::Rename { from, to } => {
                // REMOVED from the source. A rename that left the original behind would be a
                // copy, and an operator renaming `groups` to `roles` to stop leaking the
                // internal name would still be leaking it.
                if let Some(value) = working.remove(from) {
                    working.insert(to.clone(), value);
                    // The placement follows the value: a claim renamed after being placed keeps
                    // where it was put.
                    if let Some(placement) = placements.remove(from) {
                        placements.insert(to.clone(), placement);
                    }
                }
            }
            MappingRule::Static { name, value } => {
                working.insert(name.clone(), value.clone());
            }
            MappingRule::FilterList { name, allow } => {
                if let Some(serde_json::Value::Array(members)) = working.get(name) {
                    let kept: Vec<serde_json::Value> = members
                        .iter()
                        .filter(|member| {
                            member
                                .as_str()
                                .is_some_and(|text| allow.iter().any(|a| a == text))
                        })
                        .cloned()
                        .collect();
                    working.insert(name.clone(), serde_json::Value::Array(kept));
                }
                // A claim that is absent, or is not a list, is left ALONE rather than emptied.
                // Emptying it would turn a configuration mistake (filtering a string) into
                // silent data loss in every token.
            }
            MappingRule::Place { name, placement } => {
                placements.insert(name.clone(), *placement);
            }
        }
    }

    let mut mapped = MappedClaims::default();
    for (name, value) in working {
        match placements.get(&name).copied().unwrap_or(Placement::Both) {
            Placement::IdToken => {
                mapped.id_token.insert(name, value);
            }
            Placement::AccessToken => {
                mapped.access_token.insert(name, value);
            }
            Placement::Both => {
                mapped.id_token.insert(name.clone(), value.clone());
                mapped.access_token.insert(name, value);
            }
        }
    }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::{MappedClaims, MappingRule, Placement, apply, validate};
    use std::collections::BTreeMap;

    fn source() -> BTreeMap<String, serde_json::Value> {
        let mut claims = BTreeMap::new();
        claims.insert("groups".to_owned(), serde_json::json!(["eng", "sre", "hr"]));
        claims.insert("email".to_owned(), serde_json::json!("ada@example.test"));
        claims
    }

    fn only(rule: MappingRule) -> MappedClaims {
        apply(&[rule], &source()).expect("applies")
    }

    /// CRITERION 4, all four operations, with no custom code.
    #[test]
    fn the_four_declarative_operations_each_work() {
        // RENAME, and the original is GONE: a rename that left it behind is a copy, and an
        // operator renaming an internal name to stop leaking it would still be leaking it.
        let renamed = only(MappingRule::Rename {
            from: "groups".to_owned(),
            to: "roles".to_owned(),
        });
        assert_eq!(
            renamed.id_token["roles"],
            serde_json::json!(["eng", "sre", "hr"])
        );
        assert!(
            !renamed.id_token.contains_key("groups"),
            "a rename must not leave the source behind: {:?}",
            renamed.id_token
        );

        // STATIC.
        let statics = only(MappingRule::Static {
            name: "tier".to_owned(),
            value: serde_json::json!("gold"),
        });
        assert_eq!(statics.id_token["tier"], serde_json::json!("gold"));

        // GROUP FILTERING, which is the case the criterion names.
        let filtered = only(MappingRule::FilterList {
            name: "groups".to_owned(),
            allow: vec!["eng".to_owned(), "hr".to_owned()],
        });
        assert_eq!(
            filtered.access_token["groups"],
            serde_json::json!(["eng", "hr"]),
            "only the allowed members survive, in their original order"
        );

        // PLACEMENT.
        let placed = only(MappingRule::Place {
            name: "email".to_owned(),
            placement: Placement::IdToken,
        });
        assert!(placed.id_token.contains_key("email"));
        assert!(
            !placed.access_token.contains_key("email"),
            "a resource server should not need the identity to make a decision"
        );
    }

    /// A claim no rule places goes in BOTH, which is what happened before mappings existed.
    #[test]
    fn an_unplaced_claim_is_not_moved() {
        let mapped = apply(&[], &source()).expect("applies");
        for name in ["groups", "email"] {
            assert!(mapped.id_token.contains_key(name), "{name} in the id token");
            assert!(
                mapped.access_token.contains_key(name),
                "{name} in the access token"
            );
        }
    }

    /// CRITERION 5. A rule WRITING a protected claim is refused, and the refusal names it.
    ///
    /// Refused rather than ignored, and the difference is the whole point: a mapping that
    /// silently dropped a rule targeting `sub` would leave an operator believing they had
    /// rewritten the subject, and the first they would learn otherwise is a downstream system
    /// reading a `sub` they did not expect.
    #[test]
    fn a_rule_writing_a_protected_claim_is_refused_by_name() {
        for (index, rule) in [
            MappingRule::Static {
                name: "sub".to_owned(),
                value: serde_json::json!("attacker"),
            },
            MappingRule::Rename {
                from: "email".to_owned(),
                to: "iss".to_owned(),
            },
            MappingRule::Place {
                name: "aud".to_owned(),
                placement: Placement::IdToken,
            },
            MappingRule::FilterList {
                name: "exp".to_owned(),
                allow: Vec::new(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let refusal = validate(std::slice::from_ref(&rule)).expect_err("must be refused");
            assert_eq!(refusal.rule_index, 0);
            assert!(
                crate::scope_claims::is_protected_claim(&refusal.claim),
                "case {index}: the refusal must name the protected claim it stopped, got {:?}",
                refusal.claim
            );
            // And `apply` refuses the same thing, so validating on write and applying at
            // issuance cannot disagree.
            assert!(apply(&[rule], &source()).is_err(), "case {index}");
        }
    }

    /// READING a protected claim is allowed; only writing one is refused.
    ///
    /// The direction matters and is easy to get backwards. Renaming `sub` to `subject` copies
    /// the identity into a claim of the operator's choosing, which is theirs to do; renaming
    /// something INTO `sub` rewrites the identity, which is not.
    #[test]
    fn reading_a_protected_claim_is_allowed_and_only_writing_is_refused() {
        let mut claims = source();
        claims.insert("sub".to_owned(), serde_json::json!("usr_ada"));
        let mapped = apply(
            &[MappingRule::Rename {
                from: "sub".to_owned(),
                to: "subject".to_owned(),
            }],
            &claims,
        )
        .expect("renaming FROM a protected claim is allowed");
        assert_eq!(mapped.id_token["subject"], serde_json::json!("usr_ada"));
    }

    /// The refusal names the OFFENDING rule's position, not the first rule.
    #[test]
    fn the_refusal_points_at_the_rule_that_caused_it() {
        let refusal = validate(&[
            MappingRule::Static {
                name: "tier".to_owned(),
                value: serde_json::json!("gold"),
            },
            MappingRule::Static {
                name: "region".to_owned(),
                value: serde_json::json!("eu"),
            },
            MappingRule::Static {
                name: "iat".to_owned(),
                value: serde_json::json!(0),
            },
        ])
        .expect_err("must be refused");
        assert_eq!(
            refusal.rule_index, 2,
            "an operator with forty rules needs the index of the wrong one"
        );
        assert_eq!(refusal.claim, "iat");
    }

    /// A refused mapping applies NOTHING, rather than the rules before the bad one.
    #[test]
    fn a_refused_mapping_does_not_half_apply() {
        let outcome = apply(
            &[
                MappingRule::Static {
                    name: "tier".to_owned(),
                    value: serde_json::json!("gold"),
                },
                MappingRule::Static {
                    name: "sub".to_owned(),
                    value: serde_json::json!("attacker"),
                },
            ],
            &source(),
        );
        assert!(
            outcome.is_err(),
            "a mapping with a protected write is refused whole"
        );
    }

    /// Filtering a claim that is absent, or is not a list, leaves it alone.
    ///
    /// Emptying it would turn a configuration mistake into silent data loss in every token.
    #[test]
    fn filtering_a_non_list_leaves_it_alone() {
        let filtered = only(MappingRule::FilterList {
            name: "email".to_owned(),
            allow: vec!["nothing".to_owned()],
        });
        assert_eq!(
            filtered.id_token["email"],
            serde_json::json!("ada@example.test"),
            "a string is not an empty list"
        );

        let absent = only(MappingRule::FilterList {
            name: "nosuchclaim".to_owned(),
            allow: vec!["x".to_owned()],
        });
        assert!(!absent.id_token.contains_key("nosuchclaim"));
    }

    /// Rules apply IN ORDER, and the order is observable.
    #[test]
    fn rules_apply_in_the_order_given() {
        let rename_then_static = apply(
            &[
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "roles".to_owned(),
                },
                MappingRule::Static {
                    name: "roles".to_owned(),
                    value: serde_json::json!(["fixed"]),
                },
            ],
            &source(),
        )
        .expect("applies");
        assert_eq!(
            rename_then_static.id_token["roles"],
            serde_json::json!(["fixed"]),
            "the later static wins"
        );

        let static_then_rename = apply(
            &[
                MappingRule::Static {
                    name: "roles".to_owned(),
                    value: serde_json::json!(["fixed"]),
                },
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "roles".to_owned(),
                },
            ],
            &source(),
        )
        .expect("applies");
        assert_eq!(
            static_then_rename.id_token["roles"],
            serde_json::json!(["eng", "sre", "hr"]),
            "the later rename wins; the sequence is the operator's and is applied as written"
        );
    }

    /// A renamed claim keeps where it was placed.
    #[test]
    fn placement_follows_a_rename() {
        let mapped = apply(
            &[
                MappingRule::Place {
                    name: "groups".to_owned(),
                    placement: Placement::AccessToken,
                },
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "roles".to_owned(),
                },
            ],
            &source(),
        )
        .expect("applies");
        assert!(
            mapped.access_token.contains_key("roles") && !mapped.id_token.contains_key("roles"),
            "the placement follows the value: id={:?} access={:?}",
            mapped.id_token.keys().collect::<Vec<_>>(),
            mapped.access_token.keys().collect::<Vec<_>>()
        );
    }
}
