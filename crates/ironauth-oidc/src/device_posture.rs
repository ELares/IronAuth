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

use ironauth_cel::{BudgetedProgram, DEFAULT_MAX_STRING_BYTES, InputShape, compile_within_budget};
use ironauth_env::Clock;
use ironauth_jose::{ExpectedTyp, JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use serde::{Deserialize, Serialize};

/// The claim carrying the posture signals, inside the MDM's assertion.
const SIGNALS_CLAIM: &str = "device_posture";

/// The cost ceiling a posture predicate compiles under.
///
/// Deliberately small, and precise about what "small" reaches. `estimate_parsed_cost` returns
/// 1 for any comprehension-free expression, so no flat predicate over these signals can exceed
/// this at any value: what the budget bites on is COMPREHENSIONS, whose estimate grows with
/// the declared collection size raised to the nesting depth. A single-level one fits and a
/// two-level one does not, which is the boundary the test pins.
///
/// It is a CEILING on that growth rather than a rule about what a predicate may contain, and
/// an earlier version of this comment implied the second. A posture expression reading a
/// handful of booleans off one flat object has no reason to iterate at all; this is what
/// stops one that does from being expensive, not what stops it from existing.
///
/// Refusing at COMPILE time means an operator hears about it when they configure the policy
/// rather than on the request that needed it.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// The derived shape, reachable only through the object check in [`PostureSignals`]'s own
/// `Deserialize`.
/// UNKNOWN FIELDS ARE IGNORED, deliberately: an MDM adds fields on its own schedule, and a
/// decode that turned fatal on each one would break a deployment the day its vendor shipped a
/// new signal. What the schema fixes is which fields we READ, not which the vendor may send.
#[derive(Deserialize)]
struct SignalsFields {
    managed: bool,
    encrypted: bool,
    patched: bool,
    edr: EdrState,
}

/// AN OBJECT, NEVER A POSITIONAL ARRAY, and this exists because the derive accepts both.
///
/// `serde`'s derived `Deserialize` for a struct matches a JSON ARRAY by POSITION, so
/// `[true,true,true,"healthy"]` decodes exactly as the object form does. That makes FIELD ORDER
/// part of the wire contract without anybody writing it down: swapping `encrypted` and
/// `patched` in the declaration above -- a refactor that touches no serialisation code and
/// reads as cosmetic -- silently reinterprets every array-form claim, and a device reported as
/// encrypted-but-unpatched becomes patched-but-unencrypted.
///
/// A posture assertion is an object in every MDM that emits one, so nothing is lost by
/// refusing the array. What is gained is that the field NAMES are the contract, which is what
/// the struct exists to say.
impl<'de> Deserialize<'de> for PostureSignals {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if !value.is_object() {
            return Err(serde::de::Error::custom(
                "device posture signals must be a JSON object, not an array or a scalar",
            ));
        }
        let fields: SignalsFields =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            managed: fields.managed,
            encrypted: fields.encrypted,
            patched: fields.patched,
            edr: fields.edr,
        })
    }
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
    /// discarded here is discarded on purpose: the verdict a caller acts on should not vary
    /// with which way a forgery was malformed.
    ///
    /// It is discarded for good, though, and the first version of this said otherwise. No
    /// caller of [`PosturePolicy::evaluate`] can recover the detail, because the `VerifyError`
    /// never leaves this function. A deployment that wants it in a log needs this module to
    /// carry it out, which is a change to this signature rather than something an operator can
    /// reach today.
    Unverifiable,

    /// It verified and the observation is older than the configured bound.
    Stale {
        /// How old the observation was, in seconds.
        age_secs: i64,
        /// The configured bound it exceeded.
        max_age_secs: i64,
    },
    /// The clock could not be read as seconds since the epoch, so no age can be computed.
    ///
    /// Its own reason rather than folding into `Stale`: an operator seeing this has a HOST
    /// problem, not a device one, and telling them a device's posture is stale would send them
    /// to the wrong machine entirely.
    UnreadableClock,
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
    /// and behaves as a race against the clock's own resolution. A NEGATIVE bound denies every
    /// claim whose `iat` is not in the future, which is every honest one.
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
        let verification = VerificationPolicy::new(
            algorithms,
            keys,
            issuer,
            audience,
            ExpectedTyp::ForeignIssuer,
        )
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
        // `require_iat` on the policy means `verify` has already refused a claim without one,
        // so this cannot be `None` -- and an `expect` here would be a panic on a path no input
        // reaches. A reviewer measured the alternative: an explicit `NoIssuedAt` deny arm was
        // UNREACHABLE, and mutating it to an allow passed the whole suite, because nothing can
        // drive it. Two guards for one fact left the second one unmeasurable; one guard, at
        // the policy, is the one that fires.
        let issued_at = verified.claims().issued_at().unwrap_or(i64::MIN);

        // FRESHNESS, the half `verify` does not do. Measured from the same clock the
        // verification used, so a deployment with a skewed clock is wrong in one direction
        // rather than in two that can disagree.
        //
        // A CLOCK THIS CANNOT READ DENIES. The first version wrote `map_or(0, ..)`, which
        // makes `now` the epoch and therefore every claim's age NEGATIVE -- so a clock set
        // before 1970, which `SystemTime` permits and `duration_since` reports as an error,
        // turned the freshness bound off entirely. A fallback that silences an error by
        // choosing a value is a fail-open wearing a default's clothes.
        let Ok(since_epoch) = clock.now_utc().duration_since(UNIX_EPOCH) else {
            return PostureVerdict::Deny(DenyReason::UnreadableClock);
        };
        let Ok(now) = i64::try_from(since_epoch.as_secs()) else {
            return PostureVerdict::Deny(DenyReason::UnreadableClock);
        };

        // A FUTURE-DATED OBSERVATION cannot reach here, and that is worth a sentence because
        // `age_secs` going negative would otherwise sail under the bound: `age > max_age` is
        // false for a claim stamped next year. `verify` refuses an `iat` outside the policy's
        // skew before this function sees it, so the deployment's existing notion of honest
        // clock disagreement is the one that applies.
        //
        // A guard here was written and then removed. It was unreachable -- exactly the
        // two-guards-for-one-fact shape that made the `NoIssuedAt` arm unmeasurable a round
        // earlier -- and the test that would have covered it instead asserts the reason
        // `verify` produces, so relaxing the skew fails there rather than silently here.
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
        // INFALLIBLE, so no deny arm: `PostureSignals` is three booleans and a unit enum, and
        // `to_value` fails only on a custom `Serialize` that errors or a non-string map key.
        // The arm that used to be here was dead, and its mutant to an allow survived the whole
        // suite for that reason -- a deny nothing can reach is not a guard, it is a comment
        // that compiles.
        let bound = serde_json::json!({
            "managed": signals.managed,
            "encrypted": signals.encrypted,
            "patched": signals.patched,
            "edr": signals.edr,
        });

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
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}
