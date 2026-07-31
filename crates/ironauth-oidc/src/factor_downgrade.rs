// SPDX-License-Identifier: MIT OR Apache-2.0

//! The no-silent-downgrade gate: the ONE place a WEAK possession factor is refused a
//! PRIMARY login session on an account already protected by a stronger factor
//! (issue #267, generalizing the issue #70 SMS gate).
//!
//! # The defect this module exists to make impossible
//!
//! Issue #70 shipped the invariant for SMS only, as a private helper inside
//! `sms_otp.rs`. The email possession family (the email OTP of issue #68, the
//! scanner-safe magic link of issue #68, and the headless recovery journey of issue
//! #84, which drives the SAME email-OTP verify core) fell straight through to a session
//! mint on EVERY purpose with no probe at all, so an actor who controlled a mailbox
//! could mint a primary session over a passkey, and an `mfa` or `verify_address` code
//! minted a full login by itself. The gate is shared here so the two can never diverge
//! again: adding a weak factor without placing it on the ladder does not compile.
//!
//! # What "stronger" means, explicitly
//!
//! Strength is NOT a chain of conditionals. It is the issue #66 credential ladder,
//! reached through the issue #81 [`RecoveryFactor`] projection:
//!
//! 1. every gated factor names a [`RecoveryFactor`] through [`WeakFactor::factor`], an
//!    EXHAUSTIVE match, so a new weak factor fails to COMPILE until it is placed;
//! 2. a factor's rung is [`RecoveryFactor::strength_acr`], which is `AuthMethod::acr`,
//!    the codebase's single source of "stronger";
//! 3. the comparison is [`step_up::acr_satisfies`] against the CANONICAL ladder,
//!    [`step_up::default_acr_order`], and deliberately NOT against the deployment's
//!    `oidc.acr_order`.
//!
//! # Why this gate is not steerable by `oidc.acr_order`
//!
//! `oidc.acr_order` is the deployment's STEP-UP policy: how strong an already
//! authenticated session must be to clear a floor an application asked for. This gate
//! asks a different question, about the INTRINSIC strength of a credential: may a proof
//! of mailbox or phone-number control alone stand in for a passkey the account already
//! holds. That answer is a property of the credentials, not of a policy knob, so
//! reading a policy knob here would let one configuration line answer it for every
//! tenant in the deployment at once.
//!
//! It would, in fact, have done exactly that. An `acr_order` that ranks
//! `urn:ironauth:acr:pwd` ABOVE the passkey rungs, for example
//! `["phr", "phrh", "urn:ironauth:acr:attested_passkey", "urn:ironauth:acr:pwd",
//! "urn:ironauth:acr:mfa_remembered", "urn:ironauth:acr:mfa"]`, makes every weak
//! possession factor outrank every strong one, so the gate permits every downgrade on
//! every path for every tenant. That ordering was ACCEPTED at boot: the validation in
//! `ironauth-config` requires a permutation of the known rungs and pins
//! `mfa_remembered` below `mfa`, and until issue #267 it pinned nothing else. Comparing
//! against the canonical ladder removes the steering entirely; the boot validation
//! additionally refuses the ordering outright now, as defence in depth for the step-up
//! path that legitimately does read it.
//!
//! Both fixes were taken, and the second is not redundant. Two OTHER strength comparisons
//! read `state.acr_order()` for the same intrinsic-strength question this gate asks:
//! `recovery::initiate_recovery`'s `reduces_security` (the issue #81 `hold_until` delay)
//! and `recovery::gate_factor_removal`. They are outside issue #267's change and are
//! deliberately not rewired here, because altering the issue #81 hold is that issue's
//! decision to make. The boot validation is what covers them today: the inverted ordering
//! that would have turned them off is now refused before the server starts.
//!
//! # Fail closed, everywhere
//!
//! Every probe and every configuration read fails CLOSED: a store fault is a
//! [`FactorProbeError`], which every call site renders as its uniform refusal, never as
//! a permitted mint. The opt-in is only ever read as `true` from a row that exists and
//! says so, and a scope with no row at all reads as no opt-in.
//!
//! What the ladder comparison does NOT need to fail closed against is a MISSING rung.
//! The canonical order is the whole known rung set by construction, so both sides of
//! the comparison are always ranked; an unranked value is unreachable here rather than
//! merely refused. [`acr_satisfies`](step_up::acr_satisfies) still answers `false` when
//! either side is absent, which is what makes a rung added to the ladder without being
//! ranked refuse rather than silently rank at the floor, and the unit tests below pin
//! that. But it is a property of a future edit, not of any operator configuration.
//!
//! # No factor-possession timing oracle
//!
//! The account probes run UNCONDITIONALLY and are NOT short-circuited (issue #267,
//! the "Minor" finding on issue #70): the pre-#267 SMS helper returned after ONE
//! database read for a passkey holder and TWO for a TOTP holder, so the response time
//! distinguished WHICH strong factor an account held. All three probes always run, so
//! the work is identical whatever the account holds.
//!
//! The probes are also ordered so that they are not a CODE-CORRECTNESS oracle. Every
//! one-time-code surface decides this gate on the resolved subject BEFORE it judges the
//! presented code, and applies the decision only after the single-use consume, so a
//! correct-but-refused guess and a wrong guess run the same statements. See
//! `email_otp::verify_email_code` and `sms_otp::verify` for the shape, and
//! `magic_link` for the one place the ordering is not fully available and why.

use ironauth_store::{Scope, UserId};

use crate::authn::{self, AuthMethod};
use crate::recovery::{RecoveryFactor, passkey_factor};
use crate::state::OidcState;
use crate::step_up;

/// A store fault while probing the account's enrolled factors or reading the tenant's
/// downgrade opt-in. Carries no detail: the caller renders its UNIFORM refusal, so the
/// fault is never an account-state oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorProbeError;

/// A WEAK possession factor whose successful proof may not, by itself, mint a primary
/// session over a stronger enrolled factor (issue #267).
///
/// These are the factors that prove control of a DELIVERY CHANNEL (a mailbox, a phone
/// number) rather than control of a secret or a device. Every one of them is a
/// "restricted authenticator" in the NIST SP 800-63B-4 sense.
///
/// Deliberately NOT listed here (see the module docs and the issue #267 report): the
/// password login, the federated login, and the device-flow login. Each of those is a
/// different question (should enrolling a passkey RAISE the floor for every login,
/// including a password one) with a product-defining answer, not this defect's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeakFactor {
    /// A numeric email one-time code (issue #68), on the hosted `/otp/verify` surface
    /// or through the headless recovery journey (issue #84).
    EmailOtp,
    /// A scanner-safe magic link (issue #68), same-device token or cross-device short
    /// code.
    MagicLink,
    /// A numeric SMS one-time code (issue #70).
    SmsOtp,
}

impl WeakFactor {
    /// The ladder rung this factor occupies (issue #81 [`RecoveryFactor`]).
    ///
    /// This match is EXHAUSTIVE on purpose: a weak factor added to [`WeakFactor`]
    /// without a rung here fails to compile, which is the "fail loudly rather than
    /// silently rank lowest" requirement. It cannot default to the floor, because a
    /// factor that silently ranked at the floor would silently PASS the gate against a
    /// password-only account and silently fail it against everything else, which is
    /// exactly the kind of quiet mis-ranking this module exists to prevent.
    #[must_use]
    pub fn factor(self) -> RecoveryFactor {
        match self {
            // The mailbox family sits at the single-primary-factor rung: the magic link
            // and the recovery code delivery prove the SAME thing the email OTP does
            // (possession of the mailbox), so they share its rung rather than inventing
            // a parallel one.
            WeakFactor::EmailOtp | WeakFactor::MagicLink => RecoveryFactor::EmailOtp,
            WeakFactor::SmsOtp => RecoveryFactor::SmsOtp,
        }
    }

    /// The stable label for the refusal log line and the refusal metric.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WeakFactor::EmailOtp => "email_otp",
            WeakFactor::MagicLink => "magic_link",
            WeakFactor::SmsOtp => "sms_otp",
        }
    }
}

/// Every SESSION-ESTABLISHING surface a weak possession factor can reach (issue #267):
/// the STRUCTURAL registry of what this gate fences.
///
/// Each call site names its own variant when it invokes [`blocked`], so the list is not
/// documentation that can rot: a surface that stops passing its variant stops being
/// gated visibly, and a NEW surface has to add a variant to call the gate at all. The
/// issue #267 regression sweep iterates [`Self::ALL`] and drives each variant end to
/// end over HTTP, so a path that is fenced but never exercised, or listed but never
/// driven, fails the suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatedSessionPath {
    /// `POST /t/{tenant}/e/{environment}/otp/verify` (issue #68).
    EmailOtpVerify,
    /// `POST /t/{tenant}/e/{environment}/magic/consume` (issue #68), both the
    /// same-device token and the cross-device short-code paths.
    MagicLinkConsume,
    /// `POST /t/{tenant}/e/{environment}/otp/sms/verify` (issue #70).
    SmsOtpVerify,
    /// The headless recovery journey's code-verify step (issue #84), which drives the
    /// same email-OTP verify core and completes through the flow engine's mint.
    FlowRecoveryVerify,
}

impl GatedSessionPath {
    /// Every gated surface. The exhaustive matches on [`Self::factor`] and
    /// [`Self::as_str`] force a new variant to be classified; this array is the one
    /// thing the compiler does not check, so the issue #267 sweep asserts its length
    /// and drives every entry.
    pub const ALL: [GatedSessionPath; 4] = [
        GatedSessionPath::EmailOtpVerify,
        GatedSessionPath::MagicLinkConsume,
        GatedSessionPath::SmsOtpVerify,
        GatedSessionPath::FlowRecoveryVerify,
    ];

    /// The weak factor this surface presents.
    #[must_use]
    pub fn factor(self) -> WeakFactor {
        match self {
            GatedSessionPath::EmailOtpVerify | GatedSessionPath::FlowRecoveryVerify => {
                WeakFactor::EmailOtp
            }
            GatedSessionPath::MagicLinkConsume => WeakFactor::MagicLink,
            GatedSessionPath::SmsOtpVerify => WeakFactor::SmsOtp,
        }
    }

    /// The stable label for the refusal log line and the refusal metric.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GatedSessionPath::EmailOtpVerify => "email_otp_verify",
            GatedSessionPath::MagicLinkConsume => "magic_link_consume",
            GatedSessionPath::SmsOtpVerify => "sms_otp_verify",
            GatedSessionPath::FlowRecoveryVerify => "flow_recovery_verify",
        }
    }
}

/// The account's STRONGEST enrolled factor, as an `acr` on the issue #66 ladder
/// (issue #267).
///
/// Every probe runs UNCONDITIONALLY: the strongest rung is folded from all three, so
/// the database work is identical whether the account holds a passkey, a TOTP, recovery
/// codes, all of them, or none. The pre-#267 SMS helper returned after the first hit,
/// which made the response time reveal WHICH factor the account held.
///
/// The three probes and their rungs:
///
/// - a passkey, read at its TRUE rung through `strongest_strength` (attested >
///   device-bound `phrh` > synced `phr`), so an attested-passkey holder is compared at
///   the attested rung rather than a flat "has a passkey" boolean. The issue #70 helper
///   only ever asked `has_any`, which is correct for a yes/no but throws the rung away;
/// - an ACTIVE TOTP authenticator, at the `mfa` rung;
/// - an UNCONSUMED recovery code, also at the `mfa` rung. Issue #81 places
///   [`RecoveryFactor::RecoveryCode`] at `mfa` ("stands in for a second factor"), and
///   the issue #70 helper omitted it: an account whose TOTP had been removed but whose
///   recovery codes survived was treated as unprotected, so a weak factor could mint a
///   session and then redeem nothing at all. This is the SMS gate's own incompleteness,
///   fixed here rather than propagated.
///
/// Unlike `recovery::account_strength_acr`, the passkey probe is NOT skipped when the
/// deployment's WebAuthn surface is switched off: a stored passkey is still a factor the
/// account holds, and an operator toggling a deployment flag must not silently open a
/// downgrade path on every passkey-protected account in every tenant.
///
/// # Errors
///
/// [`FactorProbeError`] on any store fault. This is FAIL CLOSED at the call site: the
/// caller refuses the mint. Returning a rung on error (either the floor, which permits
/// the downgrade, or the ceiling, which silently locks the account out with no operator
/// signal) would both be worse than an explicit, logged refusal.
async fn strongest_enrolled_acr(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<&'static str, FactorProbeError> {
    let scoped = state.store().scoped(scope);
    // All three probes are issued before anything is inspected, so no branch above can
    // skip a read: the work is constant in what the account holds.
    let passkey = scoped
        .webauthn_credentials()
        .strongest_strength(subject)
        .await
        .map_err(|_| FactorProbeError)?;
    let totp = scoped
        .totp_credentials()
        .has_active(subject)
        .await
        .map_err(|_| FactorProbeError)?;
    let recovery_codes = scoped
        .recovery_codes()
        .remaining_count(subject)
        .await
        .map_err(|_| FactorProbeError)?;

    if let Some(flags) = passkey {
        // A passkey outranks every `mfa`-level factor on the ladder, so it decides the
        // rung whenever one is enrolled.
        return Ok(
            passkey_factor(flags.backup_eligible, flags.attestation_verified).strength_acr(),
        );
    }
    if totp || recovery_codes > 0 {
        return Ok(authn::acr_for_mfa());
    }
    // No stronger factor: the account sits at the single-primary-factor floor, which
    // every weak factor satisfies, so the gate is a no-op for it.
    Ok(AuthMethod::Password.acr())
}

/// THE gate: whether presenting `factor` for `subject` would be a factor DOWNGRADE that
/// this scope has not opted into (issue #267).
///
/// `true` means the caller MUST refuse the session mint. The caller is responsible for
/// making that refusal uniform with a wrong code (the issue #70 timing-equalization
/// contract: DECIDE this gate before the presented code is judged, then run the same
/// resolve, the same Argon2 compare, and the same single durable write a wrong guess
/// performs, and only THEN refuse), so a blocked strong-factor account is
/// indistinguishable from a wrong guess on an unprotected one.
///
/// `allow_downgrade` is the scope's EXPLICIT opt-in, read by the caller from its own
/// factor's configuration (`sms_config.allow_factor_downgrade` for SMS,
/// `email_factor_config.allow_factor_downgrade` for the email family). It is passed in
/// rather than read here so there is exactly one configuration source per factor and no
/// possibility of two opt-ins being OR-ed into an accidental one.
///
/// # Errors
///
/// [`FactorProbeError`] on a store fault while probing. The caller fails closed.
pub async fn blocked(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    factor: WeakFactor,
    allow_downgrade: bool,
) -> Result<bool, FactorProbeError> {
    // The probe runs even when the tenant opted in, so the opt-in never becomes a way
    // to make the request cheaper (and therefore distinguishable) than a gated one.
    let enrolled = strongest_enrolled_acr(state, scope, subject).await?;
    let presented = factor.factor().strength_acr();
    // The CANONICAL ladder, never `state.acr_order()`. Intrinsic credential strength is
    // not a deployment policy question, and reading the step-up knob here would let one
    // boot-valid `oidc.acr_order` line (`pwd` ranked above the passkey rungs) disable
    // this gate for every tenant in the deployment at once. See the module docs.
    let order = step_up::default_acr_order();
    // `acr_satisfies` is FALSE when either side is absent from the order, so a rung
    // added to the ladder without being ranked refuses rather than ranking at the floor.
    Ok(!allow_downgrade && !step_up::acr_satisfies(presented, enrolled, &order))
}

/// Record a refused downgrade on the observability plane (issue #267): one structured
/// log line and one metric, never a body difference. Called by every gated surface
/// immediately before it renders its uniform refusal, so an operator can see WHICH
/// surface refused and how often without the response revealing anything.
pub fn record_refusal(scope: Scope, path: GatedSessionPath, purpose: &str) {
    tracing::info!(
        target: "ironauth.abuse",
        tenant = %scope.tenant(),
        environment = %scope.environment(),
        path = path.as_str(),
        factor = path.factor().as_str(),
        purpose,
        "factor-downgrade refused: the account holds a stronger factor and this scope \
         has no downgrade opt-in"
    );
    metrics::counter!(
        "ironauth_factor_downgrade_refused_total",
        "path" => path.as_str(),
        "factor" => path.factor().as_str(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::{GatedSessionPath, WeakFactor};
    use crate::authn::{self, AuthMethod};
    use crate::recovery::RecoveryFactor;
    use crate::step_up::{acr_satisfies, default_acr_order};

    /// The registry must list every gated surface exactly once. The exhaustive matches
    /// on `factor` / `as_str` force a new variant to be classified, but a fixed-size
    /// array can silently lose an entry, which is precisely how a "sweep every path"
    /// test stays green while a path goes undriven.
    #[test]
    fn the_gated_path_registry_lists_every_surface_exactly_once() {
        let mut labels: Vec<&'static str> = GatedSessionPath::ALL
            .iter()
            .map(|path| path.as_str())
            .collect();
        let listed = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            listed,
            "GatedSessionPath::ALL must not repeat a surface"
        );
        assert_eq!(
            listed, 4,
            "GatedSessionPath::ALL must list every variant; add the new surface here \
             AND drive it in tests/factor_downgrade.rs"
        );
    }

    /// The ordering is the whole gate, so it is pinned rather than assumed. Every weak
    /// factor must FAIL to satisfy every strong rung, and must satisfy the
    /// single-primary-factor floor (otherwise the gate would refuse an ordinary
    /// password-only account and lock everyone out).
    #[test]
    fn every_weak_factor_ranks_below_every_strong_rung() {
        let order = default_acr_order();
        let floor = AuthMethod::Password.acr();
        let strong = [
            authn::acr_for_mfa(),
            RecoveryFactor::Passkey.strength_acr(),
            RecoveryFactor::HardwarePasskey.strength_acr(),
            RecoveryFactor::AttestedPasskey.strength_acr(),
        ];
        for factor in [
            WeakFactor::EmailOtp,
            WeakFactor::MagicLink,
            WeakFactor::SmsOtp,
        ] {
            let presented = factor.factor().strength_acr();
            assert!(
                acr_satisfies(presented, floor, &order),
                "{} must satisfy the single-primary-factor floor, or the gate would \
                 refuse a password-only account",
                factor.as_str()
            );
            for rung in strong {
                assert!(
                    !acr_satisfies(presented, rung, &order),
                    "{} must NOT satisfy the {rung} rung",
                    factor.as_str()
                );
            }
        }
    }

    /// A rung that is not in the CANONICAL order satisfies NOTHING, so a factor added to
    /// the ladder without being ranked refuses loudly instead of silently passing. This
    /// is the "fail loudly rather than silently rank lowest" contract in its one
    /// remaining dimension (the other, an unclassified `WeakFactor`, is a compile
    /// error).
    ///
    /// It is a contract against a future EDIT, not against operator configuration: the
    /// gate compares against [`default_acr_order`], which ranks the whole known rung set
    /// by construction, so no `oidc.acr_order` value can leave a shipped rung unranked
    /// here.
    #[test]
    fn an_unranked_rung_satisfies_nothing() {
        let order = default_acr_order();
        let unranked = "urn:ironauth:acr:not-in-the-order";
        assert!(
            !acr_satisfies(unranked, AuthMethod::Password.acr(), &order),
            "an unranked achieved rung must satisfy nothing, not the floor"
        );
        assert!(
            !acr_satisfies(RecoveryFactor::EmailOtp.strength_acr(), unranked, &order),
            "an unranked required rung must be satisfiable by nothing"
        );
    }

    /// Each gated surface presents the factor its route actually proves. Pinned so a
    /// future edit cannot quietly re-point (say) the magic-link surface at the SMS
    /// factor and read the wrong tenant opt-in.
    #[test]
    fn each_gated_surface_presents_its_own_factor() {
        assert_eq!(
            GatedSessionPath::EmailOtpVerify.factor(),
            WeakFactor::EmailOtp
        );
        assert_eq!(
            GatedSessionPath::FlowRecoveryVerify.factor(),
            WeakFactor::EmailOtp
        );
        assert_eq!(
            GatedSessionPath::MagicLinkConsume.factor(),
            WeakFactor::MagicLink
        );
        assert_eq!(GatedSessionPath::SmsOtpVerify.factor(), WeakFactor::SmsOtp);
    }
}
