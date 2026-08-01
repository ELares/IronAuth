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
//! [`FlowStateTag::Custom`] wire state for every STEP.
//!
//! One state escapes that flatness, and it is recorded here rather than left to be discovered.
//! A render-override (see [`render_override_states`]) is a wire state an executor emits from a
//! step WITHOUT routing, and the executor that emits one does not ask which journey it is running
//! under. [`StepKind::MfaEnroll`] is authorable in a custom artifact (unlike
//! [`StepKind::Registration`], which `ironauth-journey`'s built-in-only list refuses), so a custom
//! journey carrying an enroll step reaches the show once recovery codes interstitial and is
//! persisted on [`FlowStateTag::MfaRecoveryCodes`] for exactly as long as the acknowledgment is
//! owed. That is intended (issue #311: a user who enrolls TOTP must see the codes they were just
//! issued, on every surface that can enroll them), so the map below carries the
//! `(Custom, MfaEnroll)` arm and the executor and the map agree. Every other custom step is flat.
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
/// For a GENUINE custom journey ([`Journey::Custom`]) every STEP is the flat
/// [`FlowStateTag::Custom`], so a client renders any custom step from its `ui.nodes` alone. For one
/// of the five converging MINT-FAMILY built-in journeys, each renderable [`StepKind`] maps to the
/// real per-step wire state the built-in path emits, so a built-in-artifact-driven flow is
/// byte-identical to the hand-written built-in.
///
/// "Every step" is exact and not a synonym for "every wire state a custom flow can be seen on". A
/// custom flow authored with an [`StepKind::MfaEnroll`] step is also seen on
/// [`FlowStateTag::MfaRecoveryCodes`] while the show once interstitial (issue #311) is held, which
/// is a RENDER-OVERRIDE of the enroll step and not a step of its own; [`render_override_states`] is
/// where that state is declared, for the custom journey exactly as for login. A client rendering a
/// custom journey therefore sees `custom` on every step and that one interstitial in between.
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
            // The organization picker (issue #94, PR-B2) renders on its own per-step wire state.
            StepKind::OrgPicker => FlowStateTag::OrgPicker,
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

/// The render-override wire states a step can emit BEFORE routing (issue #92, PR 8c): the
/// non-terminal acknowledgments an executor renders via
/// [`StepOutcome::Render.state_override`](super::orchestration) while the flow stays OPEN, WITHOUT
/// advancing the compiled walk.
///
/// There are two. Registration's uniform [`FlowStateTag::RegistrationAck`]: the `register`
/// executor renders it (the closed-mode anti-enumeration ack, or the waitlist pending notice) on a
/// DIFFERENT wire state than its own [`FlowStateTag::RegistrationDetails`], but it does NOT route to
/// a distinct step (no edge, no executor of its own), so it is a render-override rather than a
/// [`wire_state_for`] step kind. Teaching [`super::inspect::project_plan`] and the
/// [`super::orchestration::builtin_step_for`] reverse-map about it keeps the projected plan and the
/// resubmit-after-ack fold faithful to the imperative driver without a phantom step or a
/// [`JOURNEY_ENGINE_VERSION`](ironauth_journey::JOURNEY_ENGINE_VERSION) bump.
///
/// [`FlowStateTag::MfaRecoveryCodes`] (issue #311) is the second, and it is the SAME shape: the
/// `mfa_enroll` executor renders the show once recovery codes the enrollment just minted, plus
/// their acknowledgment, on a DIFFERENT wire state than its own [`FlowStateTag::MfaEnroll`] while
/// the flow stays OPEN. It has no edge and no executor of its own (the acknowledgment re-enters the
/// SAME `mfa_enroll` step, which reads the persisted wire state to know it is on the
/// acknowledgment), so it is a render-override rather than a [`wire_state_for`] step kind and needs
/// no new [`StepKind`]. Teaching this map about it is what makes the projected plan carry it and
/// what makes [`super::orchestration::builtin_step_for`] fold the acknowledgment submission back
/// onto the enroll step.
///
/// It is declared for [`Journey::Custom`] as well as [`Journey::Login`], and the asymmetry with the
/// registration arm above is deliberate rather than an oversight in either direction. The executor
/// that emits a render-override does not consult the journey, so what a journey CAN emit is decided
/// by what a journey can be AUTHORED with: [`StepKind::Registration`] is on `ironauth-journey`'s
/// built-in-only list, so no custom artifact can carry one and the registration arm is unreachable
/// under [`Journey::Custom`] whether or not it is listed. [`StepKind::MfaEnroll`] is NOT on that
/// list, so a custom artifact can carry an enroll step, and such a journey does hold on the
/// interstitial. That is the behavior issue #311 wants everywhere (a user who just enrolled TOTP
/// must be shown the codes they were just issued, on a custom journey no less than on login), so
/// the arm below records it and this map stays a description of the executor rather than a wish.
/// Suppressing the interstitial for a custom journey instead would reintroduce the exact defect
/// #311 exists to remove, on that surface.
///
/// The tempting inverse, deriving the executor's override FROM this map so a custom journey stays
/// on [`FlowStateTag::Custom`], is not merely a different taste; it WEDGES the flow, and that was
/// measured rather than reasoned about. The acknowledgment arm in [`super::orchestration`]
/// discriminates on `scratch.step == FlowStateTag::MfaRecoveryCodes`, so a custom flow left on the
/// flat state re-enters the PLAIN enroll arm on its very next submission, whose first act is
/// `scratch.enroll_credential.ok_or(FlowError::NotFound)` against the credential the activating hop
/// released. Building exactly that variant and driving the journey through it turns the submission
/// after the interstitial into a `404 No such flow.`, one hop EARLIER than the acknowledgment: the
/// user is shown their codes and then cannot finish logging in at all.
///
/// Every other `(journey, kind)` has none. Recovery's ack is a REAL routed step
/// ([`StepKind::RecoveryVerify`] mapping to [`FlowStateTag::RecoveryAck`] via [`wire_state_for`]),
/// so it returns `&[]` here and keeps projecting naturally; the two are fully independent.
#[must_use]
pub(super) fn render_override_states(
    journey: Journey,
    step_kind: &StepKind,
) -> &'static [FlowStateTag] {
    match (journey, step_kind) {
        (Journey::Registration, StepKind::Registration) => &[FlowStateTag::RegistrationAck],
        (Journey::Login | Journey::Custom, StepKind::MfaEnroll) => {
            &[FlowStateTag::MfaRecoveryCodes]
        }
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_genuine_custom_journey_is_flat_for_every_kind() {
        // Every STEP of a custom journey renders on the flat Custom wire state. The show once
        // recovery codes interstitial is not a step (it is a render-override on the enroll step),
        // so it does not contradict this; see the override test below for the custom arm.
        for kind in [
            StepKind::IdentifierPassword,
            StepKind::MfaChallenge,
            StepKind::MfaEnroll,
            StepKind::ProgressiveProfiling,
            StepKind::OrgPicker,
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
        assert_eq!(
            wire_state_for(Journey::Login, &StepKind::OrgPicker),
            FlowStateTag::OrgPicker
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
    fn registration_emits_the_ack_as_a_render_override_and_nothing_else_does() {
        // Registration's uniform Ack is a render-override on the register step, not a routed step.
        assert_eq!(
            render_override_states(Journey::Registration, &StepKind::Registration),
            &[FlowStateTag::RegistrationAck]
        );
        // Every other (journey, kind) has no render-override; recovery's ack is a REAL routed step
        // (RecoveryVerify -> RecoveryAck via wire_state_for), so it is empty here.
        for kind in [
            StepKind::IdentifierPassword,
            StepKind::Terminal,
            StepKind::RecoveryStart,
            StepKind::RecoveryVerify,
        ] {
            assert!(
                render_override_states(Journey::Registration, &kind).is_empty(),
                "no override for {kind:?} under registration"
            );
        }
        for journey in [Journey::Login, Journey::Recovery, Journey::Custom] {
            assert!(
                render_override_states(journey, &StepKind::Registration).is_empty(),
                "no override for {journey:?}"
            );
        }
    }

    #[test]
    fn the_enroll_step_emits_the_show_once_recovery_codes_as_a_render_override() {
        // Issue #311: the show once recovery codes interstitial is a render-override on the
        // mfa_enroll step, NOT a step kind of its own, so the closed StepKind vocabulary (and its
        // BUILT_IN list, its JSON Schema enumeration, and the journey engine version) are untouched.
        assert_eq!(
            render_override_states(Journey::Login, &StepKind::MfaEnroll),
            &[FlowStateTag::MfaRecoveryCodes]
        );
        // And under a CUSTOM journey too, because the executor that emits the override does not
        // consult the journey and `StepKind::MfaEnroll` is authorable in a custom artifact, so a
        // custom journey with an enroll step genuinely holds on this state. This assertion is what
        // keeps the map a description of the executor rather than a claim about it; the end to end
        // proof that the two agree lives in `tests/flow_custom.rs`.
        assert_eq!(
            render_override_states(Journey::Custom, &StepKind::MfaEnroll),
            &[FlowStateTag::MfaRecoveryCodes]
        );
        // It belongs to the ENROLL step: the challenge step never mints codes.
        for kind in [
            StepKind::IdentifierPassword,
            StepKind::MfaChallenge,
            StepKind::ProgressiveProfiling,
            StepKind::OrgPicker,
            StepKind::Terminal,
        ] {
            for journey in [Journey::Login, Journey::Custom] {
                assert!(
                    render_override_states(journey, &kind).is_empty(),
                    "no override for {kind:?} under {journey:?}"
                );
            }
        }
        // Registration and recovery have no enroll step at all, so neither carries the override.
        for journey in [Journey::Registration, Journey::Recovery] {
            assert!(
                render_override_states(journey, &StepKind::MfaEnroll).is_empty(),
                "no enroll override for {journey:?}"
            );
        }
    }

    #[test]
    fn the_override_map_covers_every_journey_a_step_kind_is_authorable_under() {
        // The defect this pins (found reviewing issue #311): the registration arm was safe under a
        // custom journey only BY ACCIDENT, because `StepKind::Registration` is on
        // `ironauth-journey`'s built-in-only list and can never appear in a custom artifact. Mirror
        // that arm for a kind that is NOT on the list and the map silently stops describing the
        // executor. So assert the rule rather than the instance: for every kind an author CAN put
        // in a custom artifact, whatever override the built-in journeys declare must also be
        // declared for `Journey::Custom`, because the executor emits it either way.
        for kind in [
            StepKind::IdentifierPassword,
            StepKind::MfaChallenge,
            StepKind::MfaEnroll,
            StepKind::ProgressiveProfiling,
            StepKind::OrgPicker,
            StepKind::Registration,
            StepKind::RecoveryStart,
            StepKind::RecoveryVerify,
            StepKind::Decision,
            StepKind::Terminal,
        ] {
            if kind.is_builtin_only() {
                continue;
            }
            for journey in [
                Journey::Login,
                Journey::Registration,
                Journey::Recovery,
                Journey::Federation,
                Journey::Consent,
                Journey::Mfa,
            ] {
                for tag in render_override_states(journey, &kind) {
                    assert!(
                        render_override_states(Journey::Custom, &kind).contains(tag),
                        "{kind:?} is authorable in a custom artifact and emits {tag:?} under \
                         {journey:?}, so the Custom arm must declare it too"
                    );
                }
            }
        }
        // Non-vacuity: the sweep really did reach a kind that declares an override, so it is not
        // passing because every list it walked was empty.
        assert!(
            !StepKind::MfaEnroll.is_builtin_only(),
            "the enroll kind is authorable in a custom artifact (the case this rule exists for)"
        );
        assert!(
            !render_override_states(Journey::Login, &StepKind::MfaEnroll).is_empty(),
            "the enroll kind declares an override under login (the sweep is not vacuous)"
        );
        // And the accident the rule generalizes away from: registration's override is exempt only
        // because the kind cannot be authored, not because the executor would refuse it.
        assert!(
            StepKind::Registration.is_builtin_only(),
            "the registration kind is builtin only, which is the whole reason its arm is safe"
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
