// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wire-identity map (issue #92, PR 8a): the `(Journey, StepKind) -> FlowStateTag` projection
//! that lets a compiled-table drive emit a BUILT-IN journey's real per-step wire state instead of
//! the flat [`FlowStateTag::Custom`].
//!
//! ## Why it exists
//!
//! The custom-journey engine ([`super::orchestration`]) drives every custom step on the flat
//! [`FlowStateTag::Custom`] wire state and posts to `/flow/custom`. To CONVERGE the five
//! mint-family built-in journeys (login, MFA, profiling, registration, recovery) onto that same
//! engine WITHOUT changing a single rendered byte, the table drive must, when it is driving a
//! built-in artifact, emit the built-in's own [`Journey`] (from `flows.journey`, already stored)
//! and the built-in per-step [`FlowStateTag`]. Once the journey, the state, and the `ui.action`
//! all match a built-in golden, and the SAME `enter_step_nodes` builder runs, the rendered
//! [`super::model::Flow`] is byte-identical to the built-in path's by construction. This map is
//! that "which built-in wire state does this compiled step render as" function; it is the key to
//! the byte-equivalence gate the per-journey convergence PRs (PR 8b onward) rely on.
//!
//! ## Scope and residuals
//!
//! Only the five MINT-FAMILY journeys converge. Federation and consent STAY thin single-step
//! drivers, so their journeys are not mapped here (a flow on one of them never runs through the
//! table drive). A GENUINE custom journey ([`Journey::Custom`]) keeps the flat
//! [`FlowStateTag::Custom`] wire state for every step, exactly as before.
//!
//! ## Purity of the seam
//!
//! The pure `ironauth-journey` crate stays [`FlowStateTag`]-free: it knows only its own
//! [`StepKind`] vocabulary. This map, which pairs that vocabulary with the flow engine's wire
//! [`FlowStateTag`], lives HERE in `ironauth-oidc` where both types are in scope.
//!
//! ## PR 8a is behavior-zero
//!
//! No built-in journey is flipped onto the table in PR 8a, so the live custom drive still emits
//! [`FlowStateTag::Custom`] (the [`Journey::Custom`] arm below). This map is exercised by the
//! anti-drift projection ([`super::inspect::project_plan`]) and its unit tests; the per-journey
//! convergence PRs wire it into the live drive.

use ironauth_journey::StepKind;

use super::model::{FlowStateTag, Journey};

/// The wire [`FlowStateTag`] a compiled `step_kind` renders as when it is driven under `journey`
/// (issue #92, PR 8a).
///
/// For a GENUINE custom journey ([`Journey::Custom`]) every step is the flat
/// [`FlowStateTag::Custom`], so a client renders any custom step from its `ui.nodes` alone. For one
/// of the five converging MINT-FAMILY built-in journeys, each renderable [`StepKind`] maps to the
/// real per-step wire state the built-in path emits, so a built-in-artifact-driven flow is
/// byte-identical to the hand-written built-in.
///
/// A non-renderable kind (a decision, a terminal, or a `subflow_call` that composition already
/// inlined away) has no wire state of its own: the engine routes THROUGH it and never persists a
/// flow on it, so it folds to [`FlowStateTag::Custom`] as a defensive default it can never reach on
/// a well-formed table. A journey that does NOT converge (federation, consent, or the MFA pseudo
/// journey, none of which run through the table drive) likewise folds to the flat state.
#[must_use]
pub(super) fn wire_state_for(journey: Journey, step_kind: &StepKind) -> FlowStateTag {
    match journey {
        // Login carries the primary factor plus the in-flow MFA and profiling holds.
        Journey::Login => match step_kind {
            StepKind::IdentifierPassword => FlowStateTag::IdentifierPassword,
            StepKind::MfaChallenge => FlowStateTag::MfaChallenge,
            StepKind::MfaEnroll => FlowStateTag::MfaEnroll,
            StepKind::ProgressiveProfiling => FlowStateTag::ProgressiveProfiling,
            _ => FlowStateTag::Custom,
        },
        // Registration renders the details form; the uniform Ack is a render-override, not a step
        // kind (see [`super::orchestration::StepOutcome`]).
        Journey::Registration => match step_kind {
            StepKind::Registration => FlowStateTag::RegistrationDetails,
            _ => FlowStateTag::Custom,
        },
        // Recovery is a two-step topology: the identifier start and the uniform ack plus code.
        Journey::Recovery => match step_kind {
            StepKind::RecoveryStart => FlowStateTag::RecoveryStart,
            StepKind::RecoveryVerify => FlowStateTag::RecoveryAck,
            _ => FlowStateTag::Custom,
        },
        // A GENUINE custom journey is flat (every step is the Custom wire state), and the
        // non-converging journeys (federation and consent stay thin single-step drivers, and the
        // MFA pseudo journey is never a stored `flows.journey`) never run through the table drive,
        // so all of these fold to the flat Custom state.
        Journey::Custom | Journey::Federation | Journey::Consent | Journey::Mfa => {
            FlowStateTag::Custom
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_genuine_custom_journey_is_flat_for_every_kind() {
        for kind in [
            StepKind::IdentifierPassword,
            StepKind::MfaChallenge,
            StepKind::MfaEnroll,
            StepKind::ProgressiveProfiling,
            StepKind::Registration,
            StepKind::RecoveryStart,
            StepKind::RecoveryVerify,
            StepKind::Decision,
            StepKind::Terminal,
        ] {
            assert_eq!(
                wire_state_for(Journey::Custom, &kind),
                FlowStateTag::Custom,
                "a custom journey is flat for {kind:?}"
            );
        }
    }

    #[test]
    fn the_login_family_maps_to_its_real_wire_states() {
        assert_eq!(
            wire_state_for(Journey::Login, &StepKind::IdentifierPassword),
            FlowStateTag::IdentifierPassword
        );
        assert_eq!(
            wire_state_for(Journey::Login, &StepKind::MfaChallenge),
            FlowStateTag::MfaChallenge
        );
        assert_eq!(
            wire_state_for(Journey::Login, &StepKind::MfaEnroll),
            FlowStateTag::MfaEnroll
        );
        assert_eq!(
            wire_state_for(Journey::Login, &StepKind::ProgressiveProfiling),
            FlowStateTag::ProgressiveProfiling
        );
    }

    #[test]
    fn the_registration_and_recovery_kinds_map_to_their_wire_states() {
        assert_eq!(
            wire_state_for(Journey::Registration, &StepKind::Registration),
            FlowStateTag::RegistrationDetails
        );
        assert_eq!(
            wire_state_for(Journey::Recovery, &StepKind::RecoveryStart),
            FlowStateTag::RecoveryStart
        );
        assert_eq!(
            wire_state_for(Journey::Recovery, &StepKind::RecoveryVerify),
            FlowStateTag::RecoveryAck
        );
    }

    #[test]
    fn a_non_converging_journey_folds_to_the_flat_state() {
        // Federation, consent, and the MFA pseudo journey do not run through the table drive.
        for journey in [Journey::Federation, Journey::Consent, Journey::Mfa] {
            assert_eq!(
                wire_state_for(journey, &StepKind::IdentifierPassword),
                FlowStateTag::Custom
            );
        }
    }
}
