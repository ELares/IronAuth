// SPDX-License-Identifier: MIT OR Apache-2.0

//! Passkey and OTP funnel metrics (issue #152, criterion 5).
//!
//! The criterion asks that "passkey funnel and OTP conversion metrics populate correctly from
//! synthetic flows in an integration test". A funnel is a RATIO between two stages, so the
//! metric has to count both: how many ceremonies were offered, and how many completed. One
//! counter per stage with a shared label set is what lets a dashboard divide them.
//!
//! # Why this records the RESPONSE rather than the success path
//!
//! Every one of these handlers has many early returns: the factor is disabled, the relying
//! party is unconfigured, the origin is not related, the caller is not authenticated, the
//! challenge is missing or expired, the attestation is refused. Incrementing a counter at the
//! point where the ceremony succeeds would count the numerator and leave the denominator
//! wrong by however many of those paths fired, which makes the RATIO wrong in the flattering
//! direction: a deployment refusing most of its passkey registrations would show a conversion
//! rate near 1.
//!
//! So the recording wraps the handler and keys on the status it returned. There is exactly one
//! place a `Response` can come from, which is the thing that makes the count complete.
//!
//! # What it CANNOT see, stated because a funnel that silently misses a class is worse than none
//!
//! A request whose body does not deserialize is rejected inside axum's `Json` EXTRACTOR, before
//! the handler runs, so the wrapper never executes and the attempt is counted nowhere. Measured
//! rather than assumed: the first version of the integration test drove a malformed credential,
//! expected an `error` sample, and got zero.
//!
//! That is the right trade at this layer and it bounds what the metric MEANS: these series count
//! attempts that reached the ceremony logic, not every byte a client sent at the endpoint. A
//! client sending garbage is an HTTP-layer concern, and `ironauth_http_requests_total` already
//! counts it by route and status. Reading the funnel as "every attempt anyone made" would
//! overstate conversion for a deployment with a broken client.
//!
//! # Cardinality
//!
//! No tenant, client, or user label anywhere. The passkey series has 4 stages times 2 results
//! and the OTP series 2 channels times 2 stages times 2 results, so 8 + 8 = 16 series, fixed at
//! compile time. This said 24, which does not follow from the two products stated beside it; a
//! review caught the arithmetic. Issue #152 asks the contract to state cardinality bounds, so
//! this sentence IS that bound and being 50% high made it useless for the sizing question it
//! exists to answer. A funnel broken down per tenant is a dashboard question for a log pipeline, not a
//! metric, and the label-cardinality bound this milestone documents is the reason.

use axum::response::Response;

/// The passkey ceremony stage a sample belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyStage {
    /// A registration challenge was requested.
    RegisterChallenge,
    /// A registration was submitted for verification.
    RegisterComplete,
    /// An authentication challenge was requested.
    AuthenticateChallenge,
    /// An assertion was submitted for verification.
    AuthenticateComplete,
}

impl PasskeyStage {
    /// The `stage` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterChallenge => "register_challenge",
            Self::RegisterComplete => "register_complete",
            Self::AuthenticateChallenge => "authenticate_challenge",
            Self::AuthenticateComplete => "authenticate_complete",
        }
    }
}

/// Which channel carried a one-time code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpChannel {
    /// Emailed code.
    Email,
    /// Texted code.
    Sms,
}

impl OtpChannel {
    /// The `channel` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

/// Which half of the OTP conversion a sample belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpStage {
    /// A code was requested.
    Send,
    /// A code was submitted.
    Verify,
}

impl OtpStage {
    /// The `stage` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Verify => "verify",
        }
    }
}

/// Passkey ceremony outcomes by stage.
///
/// The emit sites below use the LITERAL rather than this constant, deliberately. The
/// metric-contract test resolves a site's metric name by reading
/// `crates/ironauth-server/src/metrics.rs`, so a name declared in this crate resolved to
/// nothing and its emit sites were skipped before any label or kind assertion ran. A review
/// demonstrated the consequence with four surviving mutations: a label no site sets, a dropped
/// label that is emitted, and the wrong `# TYPE`, all with the suite green. Every other
/// cross-crate metric in the workspace passes a literal for the same reason.
pub const PASSKEY_FUNNEL_TOTAL: &str = "ironauth_passkey_funnel_total";
/// One-time-code outcomes by channel and stage. See [`PASSKEY_FUNNEL_TOTAL`] on the literals.
pub const OTP_FUNNEL_TOTAL: &str = "ironauth_otp_funnel_total";

/// A marker a handler puts on a response whose STATUS cannot say it was a refusal.
///
/// The anti-enumeration design is why this exists. Every guard refusal on the OTP send paths
/// deliberately returns the SAME uniform 200 as a successful send, because a status that
/// differed would tell an unauthenticated caller whether an identifier exists, whether a
/// country is allowlisted, or whether a number is being pumped. That is correct, and it means
/// the status line carries no outcome information for those routes at all.
///
/// The first version of this module keyed the result label on the status alone, and a review
/// measured what that produced: three SMS sends, one delivered and two refused, recorded as
/// three `result="ok"` samples and zero errors. The metric reported the exact inverse of the
/// truth, on the refusal path that matters most, and the module's own header argued against
/// doing precisely that.
///
/// So a refusal says so out of band. The handler knows; the status cannot.
#[derive(Debug, Clone, Copy)]
pub struct Refused;

/// Mark `response` as a refusal the status line cannot express.
#[must_use]
pub fn mark_refused(mut response: Response) -> Response {
    response.extensions_mut().insert(Refused);
    response
}

/// The `result` label for `response`.
///
/// The [`Refused`] marker wins, because it is the only thing that can distinguish a uniform
/// acknowledgment from a real one. Failing that, a 2xx is `ok` and everything else is `error`,
/// INCLUDING a 3xx: a ceremony endpoint that redirects has not completed a ceremony, and
/// counting it as a success would inflate the numerator of the exact ratio this exists to
/// report.
fn result_label(response: &Response) -> &'static str {
    if response.extensions().get::<Refused>().is_some() {
        return "error";
    }
    if response.status().is_success() {
        "ok"
    } else {
        "error"
    }
}

/// Record `response` as one sample of `stage`, and return it unchanged.
#[must_use]
pub fn record_passkey(stage: PasskeyStage, response: Response) -> Response {
    metrics::counter!(
        "ironauth_passkey_funnel_total",
        "stage" => stage.as_str(),
        "result" => result_label(&response),
    )
    .increment(1);
    response
}

/// Record `response` as one sample of `channel` at `stage`, and return it unchanged.
#[must_use]
pub fn record_otp(channel: OtpChannel, stage: OtpStage, response: Response) -> Response {
    metrics::counter!(
        "ironauth_otp_funnel_total",
        "channel" => channel.as_str(),
        "stage" => stage.as_str(),
        "result" => result_label(&response),
    )
    .increment(1);
    response
}
