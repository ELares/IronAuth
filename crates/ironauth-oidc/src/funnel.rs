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
//! No tenant, client, or user label anywhere. The passkey series has 4 stages times 2 results,
//! the OTP series 2 channels times 2 stages times 2 results: 24 series total, fixed at compile
//! time. A funnel broken down per tenant is a dashboard question for a log pipeline, not a
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
pub const PASSKEY_FUNNEL_TOTAL: &str = "ironauth_passkey_funnel_total";
/// One-time-code outcomes by channel and stage.
pub const OTP_FUNNEL_TOTAL: &str = "ironauth_otp_funnel_total";

/// The `result` label for `response`.
///
/// A 2xx is the only thing counted as `ok`. Everything else is `error`, INCLUDING a 3xx: a
/// ceremony endpoint that redirects has not completed a ceremony, and counting it as a success
/// would inflate the numerator of the exact ratio this exists to report.
fn result_label(response: &Response) -> &'static str {
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
        PASSKEY_FUNNEL_TOTAL,
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
        OTP_FUNNEL_TOTAL,
        "channel" => channel.as_str(),
        "stage" => stage.as_str(),
        "result" => result_label(&response),
    )
    .increment(1);
    response
}
