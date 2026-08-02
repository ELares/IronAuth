// SPDX-License-Identifier: MIT OR Apache-2.0

//! THE recover-factor honesty rule, made STRUCTURAL (issue #295).
//!
//! The issue #81 recovery state machine holds a security-REDUCING recovery for a NOTIFIED
//! delay window. (Notified, and not yet cancellable in practice: `initiate_recovery` mints a
//! cancellation token, but the notification seam delivers a coarse per-channel alert with no
//! parameter a link could ride, so the token reaches nobody until the transport does. The
//! delay and the notification are real; the cancellation control is not deliverable yet.)
//! Whether a recovery reduces security is decided by ONE value:
//! the [`RecoveryFactor`] the recovery was performed with. A value that REACHES the
//! account's strongest factor makes `reduces_security = false`, so the flow is not held,
//! `hold_until` is never set, and the recovery can complete the moment its method
//! precondition is satisfied. An inflated value (a caller claiming
//! [`RecoveryFactor::AttestedPasskey`] when nothing at all was proven) therefore SKIPS the
//! entire delay and downgrade protection.
//!
//! Until this module existed the rule was a DOC COMMENT on
//! [`recovery::initiate_recovery`](crate::recovery::initiate_recovery): "MUST be
//! server-derived, never caller-supplied". That was safe only because the advanced-recovery
//! initiation seams were library-only and nothing mounted them. Mounting them is precisely
//! the act that turns a documented rule into an exploitable one, so the rule is now carried
//! by the type system instead of by prose.
//!
//! # The shape of the guarantee
//!
//! [`ProvenFactor`] is an opaque capability token. It has THREE private fields and NO
//! public constructor, so:
//!
//! - No code outside this module can write `ProvenFactor { .. }`: the fields are private,
//!   which is `E0451` at any struct-literal site in another module.
//! - No code outside this module can reach the one function that does write it: [`mint`] is
//!   module-private, which is `E0603` at any call site in another module.
//! - Every PRODUCTION mint in this module HARD-CODES the rung it attests. Not one of them
//!   takes a [`RecoveryFactor`] parameter, so there is no argument position anywhere in a
//!   production build into which an inflated rung could be written. Inflation is not
//!   forbidden; it is unsayable.
//!
//! The token also carries the [`Scope`] and the [`UserId`] the evidence was proven FOR, and
//! the initiation functions read all three from it rather than taking them separately. A
//! handler therefore cannot prove one account's channel and open a recovery against a
//! different account, or against a different environment: those, too, stop being rules a
//! caller could break.
//!
//! The one constructor that DOES take a rung is
//! [`ProvenFactor::fabricated_for_tests`], compiled only under the non-default `testing`
//! feature. No production binary enables it (`ironauth` does not, and no crate lists
//! `ironauth-oidc/testing` as a non-dev dependency feature), so it exists in the test
//! binaries alone.
//!
//! # What actually counts as evidence
//!
//! [`prove_email_otp`] is the only production mint that READS evidence: it drives the ONE
//! email-OTP verify core (`email_otp::verify_email_code`), on the recovery purpose, so the
//! throttle, the constant-time compare, the per-code attempt budget, and the single-use
//! consume are the same ones the `/otp/verify` surface uses. It mints exactly
//! [`RecoveryFactor::EmailOtp`], the `pwd` rung, because that is what an email one-time code
//! proves and nothing more.
//!
//! [`from_notified_channel`] is the mint for the STANDARD `/recover` surface and the
//! headless recovery journey, where no code has been presented yet and the recovery
//! instructions are DELIVERED to the resolved account's own registered channel. It reads no
//! evidence and so, like every other production mint, hard-codes the `pwd` rung: it can only
//! ever cause MORE delay, never less.

use ironauth_store::{EmailFactorPurpose, Scope, UserId};

use crate::email_otp::{self, BlockedDisposition, EmailCodeOutcome};
use crate::factor_downgrade::GatedSessionPath;
use crate::recovery::RecoveryFactor;
use crate::state::OidcState;

/// WHICH hosted recovery endpoint drove a proof (issue #295), as an observability label.
///
/// The email-OTP verify core attributes its no-silent-downgrade record to a
/// [`GatedSessionPath`], and the recovery endpoints are deliberately NOT members of that
/// enum: they are not registered session-mint surfaces, and the issue #267 sweeps over
/// `GatedSessionPath::ALL` demand no-session behaviour on exactly the protected accounts
/// recovery exists to serve, so registering them would fail those sweeps by design. This is
/// the label that makes `/recover/*` attributable anyway.
///
/// It is an enum rather than a bare string so a new hosted recovery surface has to name
/// itself here, and so the set of labels an operator can see is the set written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryProofSurface {
    /// `POST .../recover/admin-approved/initiate`.
    AdminApprovedInitiate,
    /// `POST .../recover/idv/initiate`.
    IdvInitiate,
    /// `POST .../recover/finalize`.
    Finalize,
}

impl RecoveryProofSurface {
    /// The stable label for the observability plane.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryProofSurface::AdminApprovedInitiate => "recover_admin_approved_initiate",
            RecoveryProofSurface::IdvInitiate => "recover_idv_initiate",
            RecoveryProofSurface::Finalize => "recover_finalize",
        }
    }
}

/// A recovery factor that has been ESTABLISHED SERVER SIDE, bound to the scope and the
/// subject it was established for (issue #295).
///
/// This is a capability token, not a data carrier. Holding one is proof that the code which
/// produced it did the work its rung claims; it is the ONLY thing the recovery-initiation
/// entry points accept, so "the recover factor must be server-derived" is a property the
/// compiler checks rather than a sentence a future caller can miss.
///
/// The fields are private and this module exposes no public constructor. See the module doc
/// for the two compiler errors that enforce that.
#[derive(Debug, Clone)]
pub struct ProvenFactor {
    /// The environment the evidence was proven in.
    scope: Scope,
    /// The subject the evidence was proven FOR, resolved server side (never a request field).
    subject: UserId,
    /// The rung the evidence actually reaches.
    factor: RecoveryFactor,
}

impl ProvenFactor {
    /// The environment the evidence was proven in.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The subject the evidence was proven FOR.
    #[must_use]
    pub fn subject(&self) -> &UserId {
        &self.subject
    }

    /// The rung the evidence actually reaches.
    #[must_use]
    pub fn factor(&self) -> RecoveryFactor {
        self.factor
    }

    /// Fabricate a proof at an ARBITRARY rung, for tests ONLY (issue #295).
    ///
    /// This is the one constructor anywhere that takes a [`RecoveryFactor`] as a parameter,
    /// which is exactly why it is behind the non-default `testing` feature: the recovery
    /// suites need to drive the credential ladder at rungs (`phr`, `mfa`) that no production
    /// recovery surface can prove today, and there is no production code path that would
    /// compile against it. A build that does not enable `testing`, which is every shipped
    /// binary, has no way to name a rung at a mint site at all.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn fabricated_for_tests(scope: Scope, subject: UserId, factor: RecoveryFactor) -> Self {
        mint(scope, subject, factor)
    }
}

/// THE single struct-literal site for [`ProvenFactor`], module-private (issue #295).
///
/// Every mint in this module funnels through here, and nothing outside this module can
/// call it (`E0603`) or bypass it (`E0451`), so the set of ways a proof can come into
/// existence is exactly the set of functions written below.
fn mint(scope: Scope, subject: UserId, factor: RecoveryFactor) -> ProvenFactor {
    ProvenFactor {
        scope,
        subject,
        factor,
    }
}

/// PROVE control of the account's email channel with a one-time code, and mint the `pwd`-rung
/// proof that fact supports (issue #295).
///
/// The verification is the ONE email-OTP core the `/otp/verify` surface drives
/// (`email_otp::verify_email_code`) on [`EmailFactorPurpose::Recovery`], so this surface
/// re-derives none of the email-factor security: the recovery-path throttle (issue #64, the
/// INDEPENDENT [`AuthPath::Recovery`](ironauth_store::AuthPath) counters), the anti-timing
/// dummy spend on an absent recipient, the constant-time compare through the admission
/// controlled hashing pool, the per-code attempt budget, and the single-use consume all
/// happen exactly once, here.
///
/// The subject is RESOLVED by that core from the presented identifier. It is never read from
/// a request field, so the caller cannot aim the proof at an account it did not prove.
///
/// # The issue #267 gate, and why a `Blocked` outcome is a SUCCESS here
///
/// `verify_email_code` DECIDES the no-silent-downgrade gate for a session-establishing
/// purpose, and [`EmailFactorPurpose::Recovery`] is session-establishing. This function
/// treats [`EmailCodeOutcome::Blocked`] as a SUCCESSFUL possession proof, deliberately: the
/// gate's question is "may this weak factor mint a PRIMARY session", and the answer here is
/// no, which is true and which this function honours by minting no session whatsoever. What
/// it produces is a `pwd`-rung proof, and a `pwd`-rung proof against a passkey-protected
/// account is exactly the input that makes issue #81 HOLD the recovery for the full delay
/// window with every channel notified. The recovery subsystem is the compensating control
/// for that downgrade, and it is a strictly stronger one than a flat refusal: refusing here
/// would leave a passkey holder who lost their passkey with no recovery path at all, which
/// is the case advanced recovery exists to serve.
///
/// Because this surface PROCEEDS rather than refusing, it passes
/// [`BlockedDisposition::ProceedsAsRecoveryProof`] and the core records a permitted-downgrade
/// event under `surface`'s label instead of a refusal. Recording a REFUSAL on a path that
/// then goes on to open a recovery case, or to mint a session at `/recover/finalize`, would
/// put events that ended in access onto `ironauth_factor_downgrade_refused_total` and would
/// falsify `record_refusal`'s own contract.
///
/// # The abuse counters are relaxed on a PROVEN code, on BOTH arms
///
/// A matched, consumed code is not a brute-force attempt, so both success arms call
/// `reset_after_success` on the context the core built, exactly as every other consumer of
/// that core does. Without it the independent [`AuthPath::Recovery`](ironauth_store::AuthPath)
/// counters would never relax on this path: a hosted recovery legitimately spends two attempts
/// per step (the code send and the code verify), so a multi-step case would walk into the
/// escalating throttle on the happy path and one mistyped code would push a real user over.
///
/// Returns [`None`] for a wrong, expired, over-attempted, absent, or already-consumed code,
/// for an unknown identifier, for a throttled or pool-rejected verify, and for a store fault:
/// ONE uniform refusal with no oracle for which of them it was.
pub async fn prove_email_otp(
    state: &OidcState,
    scope: Scope,
    surface: RecoveryProofSurface,
    identifier: &str,
    code: &str,
    headers: &axum::http::HeaderMap,
) -> Option<ProvenFactor> {
    // The SOLE gate on this path. `verify_email_code` does NOT check the email-OTP feature
    // toggle (only the `/otp/send` and `/otp/verify` handlers do), so an operator who turned
    // the email factor off would otherwise still have it running underneath every hosted
    // recovery endpoint.
    if !state.email_otp_enabled() {
        return None;
    }
    let outcome = email_otp::verify_email_code(
        state,
        scope,
        EmailFactorPurpose::Recovery,
        identifier,
        code,
        headers,
        GatedSessionPath::EmailOtpVerify,
        BlockedDisposition::ProceedsAsRecoveryProof {
            surface: surface.as_str(),
        },
    )
    .await;
    match outcome {
        // The code matched and was consumed single-use: channel control is proven. The two
        // arms are deliberately IDENTICAL in the work they do (the subject comes back from
        // the core on both, so neither re-resolves it), because the only difference between
        // them is the issue #267 gate's answer, which this function does not act on.
        EmailCodeOutcome::Verified { subject, ctx }
        // The code matched and was consumed single-use, and the issue #267 gate decided
        // against a PRIMARY session. Channel control is proven just the same, and the `pwd`
        // rung it mints is what routes the recovery onto the held/delay path. See above.
        | EmailCodeOutcome::Blocked { subject, ctx } => {
            state.reset_after_success(&ctx).await;
            Some(mint(scope, subject, RecoveryFactor::EmailOtp))
        }
        EmailCodeOutcome::Invalid
        | EmailCodeOutcome::Throttled(_)
        | EmailCodeOutcome::Rejected(_)
        | EmailCodeOutcome::ServerError => None,
    }
}

/// The mint for the STANDARD recovery surfaces (issue #295): `/recover` and the headless
/// recovery journey, where the recovery instructions are DELIVERED to `subject`'s own
/// registered channel and the one-time proof is presented LATER, on the completion step.
///
/// It reads no evidence, and so, like every other production mint, it takes no rung and
/// hard-codes [`RecoveryFactor::EmailOtp`]: the email one-time proof those surfaces deliver
/// through, and the weakest rung the ladder has. A mint that can only ever name the weakest
/// rung can only ever cause MORE delay, never less, so it is safe by construction in the one
/// direction that matters.
///
/// `pub(crate)` on purpose: it is the internal continuation of a subject the caller has
/// ALREADY resolved from the store, not a public way to conjure a proof.
pub(crate) fn from_notified_channel(scope: Scope, subject: UserId) -> ProvenFactor {
    mint(scope, subject, RecoveryFactor::EmailOtp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every PRODUCTION mint in this module attests the `pwd` rung and nothing stronger.
    ///
    /// This is the property that makes the structural guarantee total rather than local: the
    /// private field and the private [`mint`] stop another module from writing a rung, and
    /// this stops THIS module from handing one out. A future mint that attested a stronger
    /// rung without reading stronger evidence would fail here.
    #[test]
    fn the_channel_delivery_mint_attests_only_the_weakest_rung() {
        let (env, _clock) = ironauth_env::Env::deterministic(std::time::UNIX_EPOCH, 7);
        let scope = Scope::new(
            ironauth_store::TenantId::generate(&env),
            ironauth_store::EnvironmentId::generate(&env),
        );
        let subject = UserId::generate(&env, &scope);
        let proof = from_notified_channel(scope, subject);
        assert_eq!(proof.factor(), RecoveryFactor::EmailOtp);
        assert_eq!(
            proof.factor().strength_acr(),
            crate::authn::AuthMethod::Password.acr(),
            "the delivery mint must attest the pwd floor, so it can only ever ADD delay"
        );
        assert_eq!(proof.scope(), scope);
        assert_eq!(proof.subject(), &subject);
    }
}
