// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy predicates over SIGNED device-posture claims (issue #145 criterion 5, EXPLORATORY).
//!
//! > Exploratory posture predicates evaluate signed claims from a fixture MDM source and deny
//! > on unsigned or stale claims.
//!
//! # What an MDM claim is, and why it is not a session fact
//!
//! An MDM or EDR service (Intune, Jamf, `CrowdStrike`) knows things about a device that this
//! deployment cannot observe: whether it is enrolled, whether its disk is encrypted, whether it
//! is patched, whether an endpoint agent is running and healthy. Agentless-first, per the
//! issue: the device does not run our code and never reports about itself. What arrives is a
//! compact JWS the MDM signed, and every property of it that matters is a property of that
//! signature.
//!
//! # DENY IS THE DEFAULT, and every way of failing reaches it
//!
//! A claim that is absent, unsigned, signed by the wrong key, issued by the wrong party, older
//! than the freshness bound, or simply not satisfying the predicate all produce
//! [`PostureVerdict::Deny`] with a [`DenyReason`] naming which. The reason is for an operator
//! reading a log; the verdict is the same either way, because a posture gate that failed OPEN
//! on a malformed claim would be worse than no gate: it would report as enforced.
//!
//! # Freshness is NOT `exp`, and this is the part `ironauth-jose` does not do
//!
//! [`ironauth_jose::verify`] already refuses an expired token, a bad signature, a wrong issuer
//! or audience, an unlisted algorithm, and a header that steers trust. What it has no notion of
//! is how old the OBSERVATION is. An MDM can mint a posture assertion with a week-long `exp`
//! over a scan that ran on Monday, and every one of those checks passes on Friday while the
//! machine has been unenrolled since Tuesday.
//!
//! So `max_age` is enforced here, against `iat`, on top of verification. `require_iat` is set
//! on the policy for the same reason: a claim with no `iat` has no age, and a bound that cannot
//! be evaluated must not be treated as satisfied.
//!
//! # EXPLORATORY, and what that rules out
//!
//! This evaluates a predicate and returns a verdict. NOTHING in the data plane calls it: no
//! grant is refused, no session is ended, no token is withheld. Wiring it into an
//! authorization decision is productionizing the exploratory, which issue #145 puts out of
//! scope in as many words. The signal schema, the claim names and the predicate vocabulary are
//! all expected to move before anything depends on them.

use std::time::UNIX_EPOCH;

use ironauth_cel::{compile_within_budget, BudgetedProgram, InputShape, DEFAULT_MAX_STRING_BYTES};
use ironauth_env::Clock;
use ironauth_jose::{verify, ExpectedTyp, JwsAlgorithm, TrustedKey, VerificationPolicy};
use serde::{Deserialize, Serialize};

/// The claim carrying the posture signals, inside the MDM's assertion.
const SIGNALS_CLAIM: &str = "device_posture";

/// The cost ceiling a posture predicate compiles under.
///
/// Deliberately small. A posture expression reads a handful of booleans off one flat object;
/// it has no collections to iterate and no reason to. An expression that cannot fit here is
/// doing something this surface is not for, and refusing it at COMPILE time means an operator
/// hears about it when they configure it rather than on the request that needed it.
const PREDICATE_BUDGET: u64 = 1_000;

/// The typed signals a posture claim carries.
///
/// A STRUCT rather than the raw JSON, and the difference is the whole reason this module has a
/// schema at all. Handing an MDM's arbitrary object to a predicate makes every field name the
/// MDM happens to use into part of our contract, so a vendor renaming `isCompliant` breaks a
/// deployment's policy with no version anywhere. Decoding into named fields means an unknown
/// field is ignored and a MISSING one is a decode failure rather than a silent `false` -- and
/// a silent `false` in a posture signal is a policy that denies for the wrong reason, which is
/// as bad as one that allows for the wrong reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureSignals {
    /// Whether the device is enrolled in management.
    pub managed: bool,
    /// Whether its storage is encrypted at rest.
    pub encrypted: bool,
    /// Whether it is inside the operator's patch window.
    pub patched: bool,
    /// The endpoint-detection agent's state, as the MDM reports it.
    pub edr: EdrState,
}

/// What the EDR agent is doing, as the MDM reports it.
///
/// THREE STATES AND NOT A BOOLEAN. "Running" and "not running" leaves nowhere to put "the agent
/// is installed and has not checked in", which is the state a compromised or powered-off
/// machine is actually in, and collapsing it into either of the other two is a decision this
/// module has no business making on an operator's behalf. The predicate can distinguish them;
/// a boolean would have decided for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrState {
    /// Installed, running, and reporting healthy.
    Healthy,
    /// Installed, but not reporting -- stale, stopped, or unreachable.
    Silent,
    /// Not installed.
    Absent,
}

/// The verdict a posture evaluation reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureVerdict {
    /// The claim verified, was fresh, and satisfied the predicate.
    Allow,
    /// Everything else, with the reason named.
    Deny(DenyReason),
}

/// WHY a posture evaluation denied.
///
/// For a log line and an operator, never for a caller to branch on into an allow. Nothing here
/// turns a `DenyReason` back into [`PostureVerdict::Allow`], and a caller matching on the
/// verdict reaches a reason only inside the `Deny` arm it came from.
///
/// That is a convenience rather than a guarantee, and the first version of this comment
/// overstated it: `DenyReason` is a public enum, so a caller CAN name one on its own. What
/// stops a reason being mistaken for a verdict is the type it is returned in, not the type it
/// is declared in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// No claim was presented at all.
    Absent,
    /// The claim did not verify: unsigned, forged, wrong issuer or audience, unlisted
    /// algorithm, expired, or a header that steers trust.
    ///
    /// THIS MODULE collapses them, not `ironauth-jose`: its `VerifyError` carries a `reason()`
    /// for exactly this, and the first version of this comment blamed the wrong layer. What is
    /// discarded here is discarded on purpose -- the verdict a caller acts on should not vary
    /// with which way a forgery was malformed -- but an operator who needs the detail can have
    /// it, and a deployment that wants it in a log should take it from the error rather than
    /// from this enum.
    Unverifiable,
    /// It verified and carried no `iat`, so its age cannot be decided.
    NoIssuedAt,
    /// It verified and the observation is older than the configured bound.
    Stale {
        /// How old the observation was, in seconds.
        age_secs: i64,
        /// The configured bound it exceeded.
        max_age_secs: i64,
    },
    /// It verified and was fresh, and the signals could not be decoded.
    Malformed,
    /// Everything held and the predicate said no.
    PredicateUnsatisfied,
    /// The predicate itself failed to evaluate.
    PredicateFailed,
}

/// A compiled posture policy: who to trust, how fresh is fresh, and what to require.
pub struct PosturePolicy {
    verification: VerificationPolicy,
    max_age_secs: i64,
    predicate: BudgetedProgram,
}

/// What went wrong building a [`PosturePolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBuildError {
    /// The freshness bound was not positive.
    ///
    /// NOT because zero would deny everything -- the first version of this said so and had it
    /// exactly backwards. The bound is inclusive (`age > max_age` denies), so a `max_age` of
    /// zero ALLOWS a claim whose `iat` is this second and denies one a second older. That is a
    /// freshness policy an operator cannot have meant: it reads as "the strictest possible"
    /// and behaves as a race against the clock's own resolution. A NEGATIVE bound is worse
    /// still, denying everything including a claim minted now.
    ///
    /// Refused at build either way, because a policy whose behaviour nobody would choose is
    /// better refused where it is written than obeyed where it is used.
    MaxAgeNotPositive,
    /// The predicate did not compile, or did not fit the budget.
    Predicate(String),
    /// The verification policy was not constructible.
    Verification(String),
}

impl PosturePolicy {
    /// Build a policy from the MDM's identity, its keys, and the predicate to require.
    ///
    /// # Errors
    ///
    /// [`PolicyBuildError`] naming which half was refused.
    pub fn new(
        issuer: &str,
        audience: &str,
        keys: Vec<TrustedKey>,
        algorithms: Vec<JwsAlgorithm>,
        max_age_secs: i64,
        predicate: &str,
    ) -> Result<Self, PolicyBuildError> {
        if max_age_secs <= 0 {
            return Err(PolicyBuildError::MaxAgeNotPositive);
        }
        // `ExpectedTyp::ForeignIssuer` because the MDM mints this and we do not control its
        // header, so `typ` cannot be the separator.
        //
        // THE WEAKER OF THE TWO FORMS that variant's doc describes, and it says so rather than
        // borrowing the stronger one. Where the pinned issuer is a value no IronAuth issuer
        // can take, the separation is STRUCTURAL. Here both the keys and the issuer come from
        // OPERATOR CONFIGURATION, which is the case that doc explicitly warns about: a
        // deployment that registered its own issuer and JWKS as the MDM would have its own
        // tokens reach the signature check with `typ` unread. What stands between that and a
        // confusion is the operator not doing it, plus the audience pin and the posture claim
        // a token minted for another purpose would not carry.
        //
        // `require_iat` because `max_age_secs` is meaningless without it, and a bound that
        // cannot be evaluated must deny rather than pass.
        let verification =
            VerificationPolicy::new(algorithms, keys, issuer, audience, ExpectedTyp::ForeignIssuer)
                .map_err(|error| PolicyBuildError::Verification(format!("{error:?}")))?
                .require_iat(true);
        let shape = InputShape {
            max_collection_size: 16,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        };
        let predicate = compile_within_budget(predicate, shape, PREDICATE_BUDGET)
            .map_err(|error| PolicyBuildError::Predicate(format!("{error:?}")))?;
        Ok(Self {
            verification,
            max_age_secs,
            predicate,
        })
    }

    /// Evaluate a presented claim.
    ///
    /// `presented` is `None` when the caller had no claim to present at all, which is a DENY
    /// and not a skip: a posture gate that passes when the signal is missing enforces nothing
    /// on precisely the devices that never reported.
    #[must_use]
    pub fn evaluate(&self, presented: Option<&str>, clock: &dyn Clock) -> PostureVerdict {
        let Some(token) = presented else {
            return PostureVerdict::Deny(DenyReason::Absent);
        };
        let Ok(verified) = verify(token, &self.verification, clock) else {
            return PostureVerdict::Deny(DenyReason::Unverifiable);
        };
        let Some(issued_at) = verified.claims().issued_at() else {
            return PostureVerdict::Deny(DenyReason::NoIssuedAt);
        };

        // FRESHNESS, the half `verify` does not do. Measured from the same clock the
        // verification used, so a deployment with a skewed clock is wrong in one direction
        // rather than in two that can disagree.
        let now = clock
            .now_utc()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX));
        let age_secs = now.saturating_sub(issued_at);
        if age_secs > self.max_age_secs {
            return PostureVerdict::Deny(DenyReason::Stale {
                age_secs,
                max_age_secs: self.max_age_secs,
            });
        }

        let Some(raw) = verified.claims().get(SIGNALS_CLAIM) else {
            return PostureVerdict::Deny(DenyReason::Malformed);
        };
        let Ok(signals) = serde_json::from_value::<PostureSignals>(raw.clone()) else {
            return PostureVerdict::Deny(DenyReason::Malformed);
        };
        let Ok(bound) = serde_json::to_value(&signals) else {
            return PostureVerdict::Deny(DenyReason::Malformed);
        };

        match self.predicate.evaluate(&[("device", &bound)]) {
            Ok(serde_json::Value::Bool(true)) => PostureVerdict::Allow,
            // A predicate that returns a NON-BOOLEAN is refused rather than coerced. CEL will
            // happily yield a string or a number, and every truthiness rule anybody might pick
            // for those is a rule an operator did not write.
            Ok(_) => PostureVerdict::Deny(DenyReason::PredicateUnsatisfied),
            Err(_) => PostureVerdict::Deny(DenyReason::PredicateFailed),
        }
    }
}

/// The seconds-since-epoch a claim would carry if minted now, for a fixture.
#[must_use]
pub fn now_secs(clock: &dyn Clock) -> i64 {
    clock
        .now_utc()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
}

