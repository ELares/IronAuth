// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pure permission-claim budget (issue #98).
//!
//! A resolved permission set is uncapped by covenant, but an access token that
//! carries it has to fit an `Authorization` header. This module is the whole
//! decision that reconciles the two, and it is deliberately PURE: no clock, no
//! store, no async, no I/O.
//!
//! [`decide`] returns `Result<_, ()>` because that is the unit error
//! `crate::tokens::mint_access` returns, and the one fallible step reachable from
//! inside it is the claims serialization there. The two functions this will be
//! called from do NOT have the same signature and this module must not imply they
//! do: `mint_access` is fallible, while `build_access_token_claims` is infallible
//! and returns a bare `serde_json::Value`. Recording the outcome as an
//! operator-visible event needs the async caller and lives elsewhere.
//!
//! # The claim is complete or absent, never a prefix
//!
//! There is no truncation here and there will not be. A partial permission set is
//! indistinguishable to a resource server from a complete one, so silently
//! shortening it would be an authorization DOWNGRADE no consumer can detect.
//! [`PermissionBudgetOutcome`] accordingly has no variant carrying a partial set.
//!
//! Be precise about how much of the no-truncation guarantee lives HERE, because
//! most of it does not. This module's outcome carries no permission set at all,
//! complete or partial, so it constrains nothing about what a caller serializes.
//! What is UNCONFIGURABLE is a truncate MODE: `ironauth_config::PermissionOverflow`
//! offers none and a config naming one fails to LOAD, which is proven where that
//! enum lives, by `ironauth_config`'s
//! `the_permission_overflow_mode_is_a_closed_two_value_enum`. That the mint does
//! not truncate anyway is neither this module's property nor the type system's: a
//! truncating emitter would compile. It is held by the mint's own tests, which
//! `docs/THREAT-MODEL.md` names.
//!
//! # Withholding does not promise the token fits
//!
//! Withholding the permission claim falls back to the `roles` claim, and that is
//! NOT a guarantee that the resulting token is under the byte budget: a
//! pathological organization could exceed it on `roles` and `scope` alone. Issue
//! #98 records that as a distinct reason and deliberately takes NO action on it,
//! because the role set is documented as uncapped by covenant (see the `roles`
//! field on `crate::tokens::MintRequest`) and adding a role budget would
//! walk back a property issue #97 shipped.
//!
//! That non-goal is why [`decide`] takes the roles-only token size as a VALUE and
//! why every [`PermissionBudgetOutcome::Withheld`] carries it as
//! `roles_only_token_bytes`. It is the size of the token that actually SHIPS once
//! the claim is withheld, and it is the only number from which "the fallback is
//! itself oversize" can be computed, so it is present on both withholding reasons
//! rather than on one. The size of the token that was WITHHELD is a different
//! number and lives where it exists: on
//! [`PermissionWithheldReason::ByteExceeded`]. A count overflow settles the
//! decision before anything is serialized, so that number does not exist on that
//! path and the type offers no slot to put one.
//!
//! LIVE: [`decide`] is called from `crate::tokens::mint_at_jwt`, on both the code
//! exchange and the refresh grant, and its verdict is what shapes the emitted claim
//! and what `crate::token::record_budget_outcome` records (issue #98, PR 13).

use ironauth_config::{PermissionOverflow, TokenClaimsConfig};

/// The budget one mint is evaluated against.
///
/// A snapshot of the `[token_claims]` configuration in the units the decision
/// works in. The byte bounds are over the COMPACT token (the whole
/// `header.payload.signature` string an `Authorization` header carries), not over
/// the payload, matching how the configuration documents them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermissionBudget {
    /// The largest compact access token, in bytes, that may carry a permission
    /// claim.
    pub max_token_bytes: usize,
    /// The compact-token size above which an emitted claim is reported as
    /// approaching the budget. Nothing is withheld at this threshold.
    pub warn_token_bytes: usize,
    /// The largest number of elements one permission claim may carry.
    pub max_permission_count: usize,
    /// The element count above which an emitted claim is reported as approaching
    /// the budget. Nothing is withheld at this threshold.
    pub warn_permission_count: usize,
    /// What a withholding tells the resource server to do instead.
    pub overflow: PermissionOverflow,
}

impl PermissionBudget {
    /// Read the budget out of the `[token_claims]` configuration.
    ///
    /// The configuration fields are `u32` and these are `usize`; the widening is
    /// LOSSLESS on every target this workspace builds, because the NARROWEST
    /// supported target has 32-bit pointers, where `usize` is exactly as wide as
    /// `u32` (that is a property of the target, not of the MSRV, which is a
    /// compiler version and says nothing about pointer width). Nothing here or
    /// downstream narrows back. A narrowing cast would be the one arithmetic step
    /// that could turn a large configured bound into a small effective one, so
    /// there is none, and every field is proven against `u32::MAX` below rather
    /// than against its shipped default, which would survive a `u8` cast.
    pub fn from_config(config: &TokenClaimsConfig) -> Self {
        Self {
            max_token_bytes: config.access_token_max_bytes as usize,
            warn_token_bytes: config.access_token_warn_bytes as usize,
            max_permission_count: config.permission_claim_max_count as usize,
            warn_permission_count: config.permission_claim_warn_count as usize,
            overflow: config.permission_claim_overflow,
        }
    }
}

/// The `permissions_status` claim value a withholding puts ON THE WIRE.
///
/// Every withholding emits one, which is what keeps a budget overflow from ever
/// looking like an absent claim: a resource server that opted in and receives
/// neither `permissions` nor `permissions_status` knows the subject has no
/// organization context, and one that receives `permissions_status` knows the set
/// was withheld and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionStatus {
    /// The resource server should authorize from the `roles` claim it already
    /// receives.
    BudgetExceeded,
    /// The resource server should consult the policy decision point.
    PdpRequired,
}

impl PermissionStatus {
    /// The wire value, DELEGATED to [`PermissionOverflow::permissions_status`] rather
    /// than spelled again here.
    ///
    /// This enum and that one are 1:1 and deliberately distinct types (one is an
    /// operator's configured MODE, the other is the wire MARKER a withholding puts on
    /// a token), but they must never disagree about the two strings. Delegating makes
    /// that structural: there is exactly one place the vocabulary is written down, and
    /// the management plane, which cannot see this type, reads it from the same place.
    pub const fn as_str(self) -> &'static str {
        match self {
            PermissionStatus::BudgetExceeded => PermissionOverflow::RolesOnly.permissions_status(),
            PermissionStatus::PdpRequired => PermissionOverflow::PdpRequired.permissions_status(),
        }
    }
}

impl From<PermissionOverflow> for PermissionStatus {
    fn from(overflow: PermissionOverflow) -> Self {
        match overflow {
            PermissionOverflow::RolesOnly => PermissionStatus::BudgetExceeded,
            PermissionOverflow::PdpRequired => PermissionStatus::PdpRequired,
        }
    }
}

/// Why a complete permission set was withheld.
///
/// The withheld token's size is carried BY the reason rather than beside it,
/// because it exists on exactly one of the two paths. The element check runs
/// first and settles a count overflow without serializing anything, so on that
/// path there is no measured size to report; making the number a field of
/// [`PermissionWithheldReason::ByteExceeded`] means "count overflow with a byte
/// count" cannot be written down at all, where an `Option` beside the reason
/// would have made it merely a value nobody sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionWithheldReason {
    /// The set had more elements than the claim may carry. Nothing was
    /// serialized, so nothing was measured.
    CountExceeded,
    /// The set fit the element bound but the token carrying it would not fit the
    /// byte bound.
    ByteExceeded {
        /// The exact compact-token size the token WOULD have had with the
        /// complete permission claim, as measured.
        token_bytes: usize,
    },
}

/// What the budget decided for one mint. Returned to the async caller so it can
/// record the event; the claim shape is already decided by the time this is seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionBudgetOutcome {
    /// The complete set was emitted.
    Emitted {
        /// The exact compact-token size the emitted token has.
        token_bytes: usize,
        /// The number of elements emitted.
        count: usize,
        /// The set fits but is PAST a warn threshold (strictly above, so a value
        /// exactly at a threshold is not approaching).
        approaching: bool,
    },
    /// The complete set was WITHHELD and `permissions_status` was emitted. Never
    /// a partial set: the claim is complete or absent, never a prefix.
    Withheld {
        /// Which bound the set crossed, carrying the withheld token's measured
        /// size on the one path where that size exists.
        reason: PermissionWithheldReason,
        /// The exact compact-token size of the token that SHIPS: the roles-only
        /// form, without the permission claim. Always present, on both reasons,
        /// because it is the number a caller needs to report that the fallback is
        /// itself over the byte budget (see the module doc: that case is a
        /// deliberate non-goal, made visible rather than acted on).
        roles_only_token_bytes: usize,
        /// The number of elements that were withheld.
        count: usize,
        /// The `permissions_status` value the token carries instead.
        status: PermissionStatus,
    },
    /// No permission set was in play (no org context, or no audience opt-in).
    NotApplicable,
}

/// Decide what one mint does with a resolved permission set of `count` elements.
///
/// `count` is [`None`] when no set is in play at all, which is a configuration
/// fact rather than an overflow and produces [`PermissionBudgetOutcome::NotApplicable`]
/// with no status claim.
///
/// `base_token_bytes` is the EXACT compact-token size of the ROLES-ONLY token, the
/// claims WITHOUT a permission claim, which is what ships if this withholds. It is
/// a plain value rather than a second thunk because the mint's algorithm computes
/// it before anything else regardless (it serializes the base claims first, then
/// decides whether to add the permission claim), so demanding it costs no
/// serialization that was not already paid for.
///
/// `full_token_bytes` yields the EXACT compact-token size of the token that would
/// carry the complete set, which the caller computes from
/// `ironauth_jose::compact_len` over the fully serialized claims. It is a thunk
/// and not a value because the element check comes first and is free: a set past
/// the element bound is settled without ever serializing it, which is the point of
/// having an element bound at all on a latency-sensitive mint path. A caller must
/// therefore not do the serialization eagerly.
///
/// # Errors
///
/// Whatever `full_token_bytes` fails with, which for the mint is a claims
/// serialization failure, matching the unit error `crate::tokens::mint_access`
/// returns. The failure is PROPAGATED and never absorbed into a size: an emitted
/// claim whose measurement did not happen would be exactly the token this module
/// exists to prevent. On the count-overflow and no-set paths the thunk is not run
/// at all, so it cannot fail there.
pub(crate) fn decide<F>(
    budget: &PermissionBudget,
    count: Option<usize>,
    base_token_bytes: usize,
    full_token_bytes: F,
) -> Result<PermissionBudgetOutcome, ()>
where
    F: FnOnce() -> Result<usize, ()>,
{
    let Some(count) = count else {
        return Ok(PermissionBudgetOutcome::NotApplicable);
    };
    // The element check FIRST: it costs nothing, and a set this large would not
    // have fit the byte bound anyway.
    if count > budget.max_permission_count {
        return Ok(PermissionBudgetOutcome::Withheld {
            reason: PermissionWithheldReason::CountExceeded,
            roles_only_token_bytes: base_token_bytes,
            count,
            status: budget.overflow.into(),
        });
    }
    let full = full_token_bytes()?;
    if full > budget.max_token_bytes {
        return Ok(PermissionBudgetOutcome::Withheld {
            reason: PermissionWithheldReason::ByteExceeded { token_bytes: full },
            roles_only_token_bytes: base_token_bytes,
            count,
            status: budget.overflow.into(),
        });
    }
    Ok(PermissionBudgetOutcome::Emitted {
        token_bytes: full,
        count,
        approaching: full > budget.warn_token_bytes || count > budget.warn_permission_count,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        PermissionBudget, PermissionBudgetOutcome, PermissionStatus, PermissionWithheldReason,
        decide,
    };
    use ironauth_config::{PermissionOverflow, TokenClaimsConfig};

    /// A budget with small, distinct bounds, so an off-by-one on any of the four
    /// thresholds moves a boundary case across a decision.
    fn budget() -> PermissionBudget {
        PermissionBudget {
            max_token_bytes: 100,
            warn_token_bytes: 80,
            max_permission_count: 10,
            warn_permission_count: 8,
            overflow: PermissionOverflow::RolesOnly,
        }
    }

    /// A roles-only token size comfortably inside [`budget`], so a test that is
    /// not about the fallback's own size does not have to name one.
    const ROLES_ONLY_BYTES: usize = 40;

    /// Decide with a thunk that yields `bytes` and records that it ran, over a
    /// roles-only token of [`ROLES_ONLY_BYTES`].
    fn decide_measuring(
        budget: &PermissionBudget,
        count: Option<usize>,
        bytes: usize,
    ) -> (PermissionBudgetOutcome, bool) {
        decide_measuring_over(budget, count, ROLES_ONLY_BYTES, bytes)
    }

    /// As [`decide_measuring`], with an explicit roles-only token size.
    fn decide_measuring_over(
        budget: &PermissionBudget,
        count: Option<usize>,
        base: usize,
        bytes: usize,
    ) -> (PermissionBudgetOutcome, bool) {
        let measured = Cell::new(false);
        let outcome = decide(budget, count, base, || {
            measured.set(true);
            Ok(bytes)
        })
        .expect("the thunk succeeds");
        (outcome, measured.get())
    }

    #[test]
    fn a_count_exactly_at_the_maximum_is_emitted() {
        let (outcome, _) = decide_measuring(&budget(), Some(10), 50);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Emitted {
                token_bytes: 50,
                count: 10,
                approaching: true,
            }
        );
    }

    #[test]
    fn one_element_past_the_maximum_is_withheld() {
        let (outcome, _) = decide_measuring(&budget(), Some(11), 50);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Withheld {
                reason: PermissionWithheldReason::CountExceeded,
                roles_only_token_bytes: ROLES_ONLY_BYTES,
                count: 11,
                status: PermissionStatus::BudgetExceeded,
            }
        );
    }

    #[test]
    fn a_token_exactly_at_the_byte_maximum_is_emitted() {
        let (outcome, _) = decide_measuring(&budget(), Some(1), 100);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Emitted {
                token_bytes: 100,
                count: 1,
                approaching: true,
            }
        );
    }

    #[test]
    fn one_byte_past_the_maximum_is_withheld() {
        let (outcome, _) = decide_measuring(&budget(), Some(1), 101);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Withheld {
                reason: PermissionWithheldReason::ByteExceeded { token_bytes: 101 },
                roles_only_token_bytes: ROLES_ONLY_BYTES,
                count: 1,
                status: PermissionStatus::BudgetExceeded,
            }
        );
    }

    #[test]
    fn exactly_at_both_warn_thresholds_is_not_approaching() {
        let (outcome, _) = decide_measuring(&budget(), Some(8), 80);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Emitted {
                token_bytes: 80,
                count: 8,
                approaching: false,
            }
        );
    }

    #[test]
    fn one_byte_past_the_warn_threshold_is_approaching() {
        let (outcome, _) = decide_measuring(&budget(), Some(8), 81);
        assert!(matches!(
            outcome,
            PermissionBudgetOutcome::Emitted {
                approaching: true,
                ..
            }
        ));
    }

    #[test]
    fn one_element_past_the_warn_threshold_is_approaching() {
        let (outcome, _) = decide_measuring(&budget(), Some(9), 80);
        assert!(matches!(
            outcome,
            PermissionBudgetOutcome::Emitted {
                approaching: true,
                ..
            }
        ));
    }

    #[test]
    fn a_count_overflow_never_serializes_the_full_form() {
        // The ordering is observable: the thunk is the serialization, and an
        // element count past the bound settles the decision without running it.
        let (_, measured) = decide_measuring(&budget(), Some(11), 50);
        assert!(!measured, "the count check must settle it before measuring");

        let (_, measured) = decide_measuring(&budget(), Some(10), 50);
        assert!(measured, "a count within the bound must be measured");
    }

    #[test]
    fn no_permission_set_is_not_applicable_and_is_never_measured() {
        let (outcome, measured) = decide_measuring(&budget(), None, 50);
        assert_eq!(outcome, PermissionBudgetOutcome::NotApplicable);
        assert!(!measured, "an absent set must not be measured");
    }

    #[test]
    fn both_overflow_modes_withhold_the_whole_set_and_say_so() {
        for (mode, status) in [
            (
                PermissionOverflow::RolesOnly,
                PermissionStatus::BudgetExceeded,
            ),
            (
                PermissionOverflow::PdpRequired,
                PermissionStatus::PdpRequired,
            ),
        ] {
            let budget = PermissionBudget {
                overflow: mode,
                ..budget()
            };
            for (count, bytes) in [(11_usize, 50_usize), (1, 101)] {
                let (outcome, _) = decide_measuring(&budget, Some(count), bytes);
                let PermissionBudgetOutcome::Withheld {
                    status: emitted,
                    count: withheld,
                    ..
                } = outcome
                else {
                    panic!("{mode:?} with count {count} and {bytes} bytes must withhold");
                };
                assert_eq!(emitted, status, "{mode:?} status");
                assert_eq!(withheld, count, "{mode:?} withholds the WHOLE set");
            }
        }
    }

    #[test]
    fn the_two_status_values_are_the_wire_vocabulary() {
        assert_eq!(PermissionStatus::BudgetExceeded.as_str(), "budget_exceeded");
        assert_eq!(PermissionStatus::PdpRequired.as_str(), "pdp_required");
    }

    #[test]
    fn a_zero_count_budget_withholds_every_nonempty_set_and_emits_the_empty_one() {
        let budget = PermissionBudget {
            max_permission_count: 0,
            warn_permission_count: 0,
            ..budget()
        };
        let (outcome, measured) = decide_measuring(&budget, Some(1), 10);
        assert!(matches!(
            outcome,
            PermissionBudgetOutcome::Withheld {
                reason: PermissionWithheldReason::CountExceeded,
                ..
            }
        ));
        assert!(!measured);

        // An empty set still fits a zero bound, and is a meaningful claim: it says
        // the subject is in an organization and holds nothing.
        let (outcome, _) = decide_measuring(&budget, Some(0), 10);
        assert!(matches!(
            outcome,
            PermissionBudgetOutcome::Emitted { count: 0, .. }
        ));
    }

    #[test]
    fn the_shipped_configuration_widens_losslessly() {
        let config = TokenClaimsConfig::default();
        let budget = PermissionBudget::from_config(&config);
        assert_eq!(
            budget.max_token_bytes,
            config.access_token_max_bytes as usize
        );
        assert_eq!(
            budget.warn_token_bytes,
            config.access_token_warn_bytes as usize
        );
        assert_eq!(
            budget.max_permission_count,
            config.permission_claim_max_count as usize
        );
        assert_eq!(
            budget.warn_permission_count,
            config.permission_claim_warn_count as usize
        );
        assert_eq!(budget.overflow, config.permission_claim_overflow);
    }

    #[test]
    fn the_largest_configurable_bounds_survive_the_widening() {
        // The widening is the one place a large configured bound could become a
        // small effective one. `u32::MAX` is past every ceiling config load
        // admits, which is exactly why it is the value to prove against.
        let config = TokenClaimsConfig {
            access_token_max_bytes: u32::MAX,
            access_token_warn_bytes: u32::MAX,
            permission_claim_max_count: u32::MAX,
            permission_claim_warn_count: u32::MAX,
            permission_claim_overflow: PermissionOverflow::PdpRequired,
        };
        let budget = PermissionBudget::from_config(&config);
        // All FOUR numeric fields, not the two bounds only. A narrowing on a warn
        // threshold is just as reachable: `permission_claim_warn_count` may be
        // configured up to the 4096 ceiling, so a `u8` cast would turn a
        // configured 300 into 44 while the shipped 192 default survived untouched.
        assert_eq!(budget.max_token_bytes, u32::MAX as usize);
        assert_eq!(budget.warn_token_bytes, u32::MAX as usize);
        assert_eq!(budget.max_permission_count, u32::MAX as usize);
        assert_eq!(budget.warn_permission_count, u32::MAX as usize);
        // And the overflow mode, which is asserted HERE because here it is
        // `PdpRequired`. The default-config test cannot prove the mapping reads
        // the field at all, since the value it expects is the same `RolesOnly` a
        // hardcoded mapping would return. Getting this wrong would tell a resource
        // server to authorize from `roles` when the operator asked it to consult
        // the policy decision point.
        assert_eq!(budget.overflow, PermissionOverflow::PdpRequired);
        assert_eq!(budget.overflow, config.permission_claim_overflow);

        let (outcome, _) = decide_measuring(&budget, Some(1_000_000), 1_000_000);
        assert!(matches!(outcome, PermissionBudgetOutcome::Emitted { .. }));
    }

    #[test]
    fn a_withholding_reports_a_roles_only_size_that_may_itself_be_oversize() {
        // The deliberate non-goal issue #98 names: withholding falls back to
        // `roles`, and the roles set is uncapped by covenant, so the token that
        // SHIPS after a withholding can itself exceed the byte budget. Nothing
        // here refuses or trims it; the outcome carries the number, and
        // `crate::token::record_budget_outcome` computes the distinct
        // `roles_only_still_oversize` event reason from it. Without this the
        // roles-only size would not exist on the outcome at all.
        let budget = budget();
        let oversize_base = budget.max_token_bytes + 20;
        for (count, full) in [(11_usize, 500_usize), (1, 101)] {
            let (outcome, _) = decide_measuring_over(&budget, Some(count), oversize_base, full);
            let PermissionBudgetOutcome::Withheld {
                roles_only_token_bytes,
                ..
            } = outcome
            else {
                panic!("count {count} with {full} bytes must withhold");
            };
            assert_eq!(
                roles_only_token_bytes, oversize_base,
                "the roles-only size is reported on both withholding reasons"
            );
            assert!(
                roles_only_token_bytes > budget.max_token_bytes,
                "and it is the number that makes a still-oversize fallback visible"
            );
        }
    }

    #[test]
    fn a_measurement_failure_propagates_and_is_never_absorbed_into_a_size() {
        // The `# Errors` contract. Absorbing the failure into a number (a `0`, a
        // `usize::MAX`) would emit a permission claim after a measurement that did
        // not happen, or withhold one for a size nothing observed.
        let budget = budget();
        assert_eq!(
            decide(&budget, Some(1), ROLES_ONLY_BYTES, || Err(())),
            Err(()),
            "a serialization failure must propagate"
        );

        // And the thunk is not reached at all once the element check has settled
        // the decision, so a set past the count bound is decided even when
        // measuring it WOULD have failed.
        let outcome = decide(&budget, Some(11), ROLES_ONLY_BYTES, || Err(()));
        assert_eq!(
            outcome,
            Ok(PermissionBudgetOutcome::Withheld {
                reason: PermissionWithheldReason::CountExceeded,
                roles_only_token_bytes: ROLES_ONLY_BYTES,
                count: 11,
                status: PermissionStatus::BudgetExceeded,
            }),
            "a failing thunk on the count path proves it was never run"
        );
        let absent = decide(&budget, None, ROLES_ONLY_BYTES, || Err(()));
        assert_eq!(
            absent,
            Ok(PermissionBudgetOutcome::NotApplicable),
            "an absent set is settled without measuring, so it cannot fail"
        );
    }

    #[test]
    fn a_zero_byte_budget_withholds_every_token() {
        // The posture the config documents alongside the zero count bound: at
        // `max_token_bytes = 0` no token can carry the claim, and the boundary is
        // uniform with the count bound (at-the-maximum still emits, so a token of
        // 0 bytes would emit, which no real token is).
        let budget = PermissionBudget {
            max_token_bytes: 0,
            warn_token_bytes: 0,
            ..budget()
        };
        let (outcome, measured) = decide_measuring(&budget, Some(1), 1);
        assert_eq!(
            outcome,
            PermissionBudgetOutcome::Withheld {
                reason: PermissionWithheldReason::ByteExceeded { token_bytes: 1 },
                roles_only_token_bytes: ROLES_ONLY_BYTES,
                count: 1,
                status: PermissionStatus::BudgetExceeded,
            }
        );
        assert!(measured, "the byte bound is reached only by measuring");
    }
}
