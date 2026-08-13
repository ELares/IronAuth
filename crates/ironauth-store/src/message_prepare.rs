// SPDX-License-Identifier: MIT OR Apache-2.0

//! Composing one outgoing message from the four hygiene and template cores (issue #111).
//!
//! [`message_template`](crate::message_template) chooses which template renders,
//! [`message_render`](crate::message_render) fills it safely,
//! [`message_mime`](crate::message_mime) assembles the body, and
//! [`message_hygiene`](crate::message_hygiene) decides whether to send at all. Each was built
//! and tested alone. Four modules that never call each other are four modules that might not
//! FIT each other, and a seam that only appears when the delivery worker is written is a seam
//! nobody has tested.
//!
//! So this is the composition, still pure and still sans-IO: given every candidate template,
//! the recipient, the values, and the suppression state, produce either a message ready to hand
//! to a transport or the reason there is none.
//!
//! # The order of the checks is the design
//!
//! Hygiene runs FIRST, before any template is chosen or rendered. Rendering a message for a
//! suppressed recipient and then discarding it wastes nothing much, but it does put user data
//! through the renderer and into memory for a message that must not exist, and it makes the
//! logs read as though a send was prepared when policy had already refused it.
//!
//! Dedup is NOT decided here. This returns the key; whether that key has been seen is a
//! question only the store can answer, and a pure function that pretended to answer it would
//! have to lie. The distinction matters: [`PreparedMessage::dedup_key`] existing does not mean
//! the message should be sent, only that the caller now has the key it needs to find out.

use std::collections::BTreeSet;

use crate::message_hygiene::{BlockReason, dedup_key, normalize_recipient, suppression_check};
use crate::message_mime::{MimeError, message_id, multipart_alternative};
use crate::message_rate::{RateBudget, RateDecision, rate_decision};
use crate::message_render::{RenderContext, RenderError, RenderMode, render, render_header};
use crate::message_template::{Locale, TemplateCandidate, TemplateLevel, resolve_template};

/// Why no message was produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError {
    /// Policy refused the send. Carries the reason so it can be recorded and queried.
    Blocked(BlockReason),
    /// The per-recipient rate limit refused this send.
    ///
    /// Distinct from [`PrepareError::Blocked`] because the two are opposites in every way that
    /// matters operationally: a suppression is PERMANENT and the caller should stop asking,
    /// while this is TEMPORARY and carries the instant a retry could succeed. Folding them
    /// together would have a caller either give up on a send that would work in a minute, or
    /// retry forever one that never will.
    RateLimited {
        /// The epoch second at which this recipient's oldest counted send leaves the window.
        retry_after_epoch_seconds: u64,
    },
    /// No template exists at any level, so there is nothing to render.
    ///
    /// A programming error in practice: the caller is expected to include the shipped
    /// [`TemplateLevel::Default`] template, which makes this unreachable.
    NoTemplate,
    /// A template failed to render.
    Render(RenderError),
    /// The message could not be assembled.
    Mime(MimeError),
}

/// A message ready for a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMessage {
    /// The normalized recipient. The transport addresses THIS, not the raw input, so the
    /// address that was suppression-checked is the address that gets mail.
    pub recipient: String,
    /// The rendered `Subject` header value.
    pub subject: String,
    /// The `Message-ID` header value, angle brackets included.
    pub message_id: String,
    /// The assembled `multipart/alternative` body.
    pub body: String,
    /// The boundary the caller must repeat in the outer `Content-Type` header.
    pub boundary: String,
    /// The key identifying this send for deduplication.
    ///
    /// Its presence does NOT mean the message should be sent. Whether this key has already
    /// been seen inside the window is a store question, and this module cannot answer it.
    pub dedup_key: String,
    /// Which template level was used, for the "why did this recipient get English?" question.
    pub template_level: TemplateLevel,
    /// The locale actually rendered, which may not be the one requested.
    pub template_locale: Locale,
    /// Whether the requested locale was unavailable.
    pub locale_fallback_applied: bool,
}

/// Everything one send needs.
pub struct PrepareRequest<'a> {
    /// The message kind, which participates in the dedup key.
    pub kind: &'a str,
    /// The recipient as written. Normalized before anything else looks at it.
    pub recipient: &'a str,
    /// Every template that exists for this kind, at any level and locale.
    pub candidates: &'a [TemplateCandidate],
    /// The recipient's preferred locale.
    pub requested_locale: &'a Locale,
    /// The environment's fallback locale.
    pub default_locale: &'a Locale,
    /// The subject template, and the text and HTML body templates, keyed by the resolved
    /// template's `body_ref`. Supplied by the caller because loading them is IO.
    pub bodies: &'a dyn Fn(&str) -> Option<MessageBodies>,
    /// The values the templates interpolate.
    pub values: &'a RenderContext,
    /// Suppressed addresses, normalized.
    pub suppressed_addresses: &'a BTreeSet<String>,
    /// Suppressed domains, normalized.
    pub suppressed_domains: &'a BTreeSet<String>,
    /// The dedup window this send falls in.
    pub window: u64,
    /// Epoch-second timestamps of prior sends to this recipient, for the rate limit. Any order;
    /// entries outside the budget window are ignored.
    pub recent_sends: &'a [u64],
    /// The per-recipient send budget.
    pub rate_budget: RateBudget,
    /// The evaluation instant in epoch seconds. Passed rather than read, so this stays pure.
    pub now_epoch_seconds: u64,
    /// The unique local part for the `Message-ID`. The caller owns uniqueness; this crate
    /// holds no clock and no randomness.
    pub message_id_local: &'a str,
    /// The sending domain, for the `Message-ID`.
    pub message_id_domain: &'a str,
    /// The multipart boundary. Supplied rather than generated for the same reason: it must be
    /// unpredictable, and unpredictability needs randomness this crate does not have.
    pub boundary: &'a str,
}

/// The three templates one message renders from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageBodies {
    /// The `Subject` template.
    pub subject: String,
    /// The plain-text body template.
    pub text: String,
    /// The HTML body template.
    pub html: String,
}

/// Prepare one message, or explain why there is none.
///
/// # Errors
///
/// [`PrepareError`], which distinguishes a policy refusal from a template, rendering or
/// assembly failure. A caller records the first and alerts on the rest: a blocked send is the
/// system working, and a render failure is a broken template someone has to fix.
pub fn prepare_message(request: &PrepareRequest<'_>) -> Result<PreparedMessage, PrepareError> {
    // Hygiene FIRST. Rendering a message for a recipient who must not receive one puts their
    // data through the renderer for a message that should not exist, and makes the logs read
    // as though a send was prepared when policy had already refused it.
    if let Some(reason) = suppression_check(
        request.recipient,
        request.suppressed_addresses,
        request.suppressed_domains,
    ) {
        return Err(PrepareError::Blocked(reason));
    }
    // Unreachable in practice: `suppression_check` already blocks anything that does not
    // normalize, so reaching here means it IS a mailbox. Handled rather than unwrapped, so a
    // future change to that ordering cannot turn into a panic in the send path.
    let Some(recipient) = normalize_recipient(request.recipient) else {
        return Err(PrepareError::Blocked(BlockReason::AddressSuppressed));
    };

    // The rate limit runs AFTER suppression and BEFORE anything is rendered.
    //
    // After suppression, because a suppressed recipient must not consume rate budget: they are
    // never going to receive this, and letting a refused send count against the limit would let
    // an attacker exhaust a victim's budget using addresses that were already blocked.
    //
    // Before rendering, for the same reason suppression is: a send that will not happen must
    // not put user data through the renderer first.
    if let RateDecision::Block {
        retry_after_epoch_seconds,
    } = rate_decision(
        request.recent_sends,
        request.now_epoch_seconds,
        request.rate_budget,
    ) {
        return Err(PrepareError::RateLimited {
            retry_after_epoch_seconds,
        });
    }

    let Some(resolved) = resolve_template(
        request.candidates,
        request.requested_locale,
        request.default_locale,
    ) else {
        return Err(PrepareError::NoTemplate);
    };
    let Some(bodies) = (request.bodies)(&resolved.body_ref) else {
        return Err(PrepareError::NoTemplate);
    };

    // The subject goes through the HEADER path, which refuses control characters outright: a
    // newline in a subject does not render oddly, it ends the header and everything after
    // becomes one an attacker chose.
    let subject = render_header(&bodies.subject, request.values).map_err(PrepareError::Render)?;
    let text =
        render(&bodies.text, request.values, RenderMode::Text).map_err(PrepareError::Render)?;
    let html =
        render(&bodies.html, request.values, RenderMode::Html).map_err(PrepareError::Render)?;

    let message_id_value = message_id(request.message_id_local, request.message_id_domain)
        .map_err(PrepareError::Mime)?;
    let body = multipart_alternative(&text, &html, request.boundary).map_err(PrepareError::Mime)?;

    // The NORMALIZED recipient is passed, though `dedup_key` normalizes again internally, so
    // passing the raw address here would produce the identical key. A mutation doing exactly
    // that survives the suite, which is the evidence for that claim rather than an argument
    // for it. Passing the normalized value anyway keeps this call site readable as "the same
    // identity suppression just checked", instead of relying on a callee's behaviour.
    let Some(key) = dedup_key(request.kind, &recipient, request.window) else {
        return Err(PrepareError::Blocked(BlockReason::AddressSuppressed));
    };

    Ok(PreparedMessage {
        recipient,
        subject,
        message_id: message_id_value,
        body,
        boundary: request.boundary.to_owned(),
        dedup_key: key,
        template_level: resolved.level,
        template_locale: resolved.locale,
        locale_fallback_applied: resolved.locale_fallback_applied,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{MessageBodies, PrepareError, PrepareRequest, prepare_message};
    use crate::message_hygiene::{BlockReason, dedup_key};
    use crate::message_rate::RateBudget;
    use crate::message_render::RenderContext;
    use crate::message_template::{Locale, TemplateCandidate, TemplateLevel};

    /// A fixed evaluation instant for the rate-limit fields.
    const NOW: u64 = 1_800_000_000;

    fn candidate(level: TemplateLevel, locale: &str) -> TemplateCandidate {
        TemplateCandidate {
            level,
            locale: Locale::new(locale),
            body_ref: format!("{level:?}/{locale}"),
        }
    }

    // The Option is the CALLBACK's contract, not this helper's choice: `PrepareRequest::bodies`
    // must be able to report a missing template, and the missing-bodies test below supplies a
    // closure that does. This fixture simply always finds one.
    #[allow(clippy::unnecessary_wraps)]
    fn bodies_for(reference: &str) -> Option<MessageBodies> {
        Some(MessageBodies {
            subject: format!("Verify your account, {{{{name}}}} [{reference}]"),
            text: "Hi {{name}}, open {{link}}".to_owned(),
            html: "<p>Hi {{name}}, <a href=\"{{link}}\">open</a></p>".to_owned(),
        })
    }

    fn values(pairs: &[(&str, &str)]) -> RenderContext {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    struct Fixture {
        candidates: Vec<TemplateCandidate>,
        requested: Locale,
        default: Locale,
        values: RenderContext,
        suppressed_addresses: BTreeSet<String>,
        suppressed_domains: BTreeSet<String>,
        recent_sends: Vec<u64>,
        rate_budget: RateBudget,
        now_epoch_seconds: u64,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                candidates: vec![
                    candidate(TemplateLevel::Default, "en"),
                    candidate(TemplateLevel::Organization, "pt-BR"),
                ],
                requested: Locale::new("pt-BR"),
                default: Locale::new("en"),
                values: values(&[("name", "Ada"), ("link", "https://example.test/v")]),
                suppressed_addresses: BTreeSet::new(),
                suppressed_domains: BTreeSet::new(),
                recent_sends: Vec::new(),
                rate_budget: RateBudget::new(3, 60),
                now_epoch_seconds: NOW,
            }
        }

        fn request<'a>(&'a self, recipient: &'a str) -> PrepareRequest<'a> {
            PrepareRequest {
                kind: "verify",
                recipient,
                candidates: &self.candidates,
                requested_locale: &self.requested,
                default_locale: &self.default,
                bodies: &bodies_for,
                values: &self.values,
                suppressed_addresses: &self.suppressed_addresses,
                suppressed_domains: &self.suppressed_domains,
                window: 42,
                recent_sends: &self.recent_sends,
                rate_budget: self.rate_budget,
                now_epoch_seconds: self.now_epoch_seconds,
                message_id_local: "msg_01ABC",
                message_id_domain: "mail.example.test",
                boundary: "ironauth-boundary-01",
            }
        }
    }

    /// The four cores compose: one call yields a message with every part filled in.
    #[test]
    fn a_complete_message_is_prepared_from_the_four_cores() {
        let fixture = Fixture::new();
        let prepared = prepare_message(&fixture.request("Ada@Example.Test")).expect("prepared");

        // Hygiene normalized the recipient, and the transport addresses THAT.
        assert_eq!(prepared.recipient, "ada@example.test");
        // Resolution chose the organization override in the requested locale.
        assert_eq!(prepared.template_level, TemplateLevel::Organization);
        assert_eq!(prepared.template_locale, Locale::new("pt-BR"));
        assert!(!prepared.locale_fallback_applied);
        // Rendering filled all three templates.
        assert!(prepared.subject.starts_with("Verify your account, Ada"));
        assert!(
            prepared
                .body
                .contains("Hi Ada, open https://example.test/v")
        );
        // MIME assembled a well-formed body.
        assert!(prepared.body.starts_with("--ironauth-boundary-01\r\n"));
        assert!(prepared.body.ends_with("--ironauth-boundary-01--\r\n"));
        assert_eq!(prepared.message_id, "<msg_01ABC@mail.example.test>");
        // And the dedup key is the one hygiene would derive for this recipient.
        assert_eq!(
            prepared.dedup_key,
            dedup_key("verify", "ada@example.test", 42).expect("a key"),
        );
    }

    /// The HTML part is escaped and the text part is not, in ONE message.
    ///
    /// The two modes are tested separately in `message_render`; what this pins is that the
    /// composition routes each body to the right one. Wiring them the other way round would
    /// pass every test in that module.
    #[test]
    fn the_composition_routes_each_body_to_the_right_escaping() {
        let mut fixture = Fixture::new();
        fixture.values = values(&[
            ("name", "<script>alert(1)</script>"),
            ("link", "https://example.test/v?a=1&b=2"),
        ]);
        let prepared = prepare_message(&fixture.request("ada@example.test")).expect("prepared");

        let (text_part, html_part) = prepared
            .body
            .split_once("Content-Type: text/html")
            .expect("both parts");
        assert!(
            text_part.contains("<script>alert(1)</script>"),
            "the text part must be verbatim: {text_part}"
        );
        assert!(
            html_part.contains("&lt;script&gt;"),
            "the html part must be escaped: {html_part}"
        );
        assert!(
            !html_part.contains("<script>"),
            "markup must not survive into the html part: {html_part}"
        );
    }

    /// Hygiene runs BEFORE rendering, so a suppressed recipient's data never reaches it.
    #[test]
    fn a_suppressed_recipient_is_blocked_before_anything_is_rendered() {
        let mut fixture = Fixture::new();
        fixture.suppressed_addresses = ["ada@example.test".to_owned()].into_iter().collect();
        assert_eq!(
            prepare_message(&fixture.request("Ada@Example.Test")).unwrap_err(),
            PrepareError::Blocked(BlockReason::AddressSuppressed),
        );
    }

    #[test]
    fn a_suppressed_domain_blocks_with_its_own_reason() {
        let mut fixture = Fixture::new();
        fixture.suppressed_domains = ["example.test".to_owned()].into_iter().collect();
        assert_eq!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::Blocked(BlockReason::DomainSuppressed),
        );
    }

    /// A subject whose value carries a newline is refused, because the subject goes through
    /// the HEADER path rather than the body path.
    ///
    /// Routing it through the body renderer would pass every test in `message_render` and ship
    /// header injection, which is why this is asserted on the composition.
    #[test]
    fn a_newline_in_a_subject_value_is_refused_by_the_composition() {
        let mut fixture = Fixture::new();
        fixture.values = values(&[
            ("name", "Ada\r\nBcc: attacker@example.test"),
            ("link", "https://example.test/v"),
        ]);
        let error = prepare_message(&fixture.request("ada@example.test")).unwrap_err();
        assert!(
            matches!(error, PrepareError::Render(_)),
            "expected a render refusal, got {error:?}"
        );
    }

    /// A missing value fails the whole message rather than sending one with a hole in it.
    #[test]
    fn a_missing_value_fails_the_message() {
        let mut fixture = Fixture::new();
        fixture.values = values(&[("name", "Ada")]);
        assert!(matches!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::Render(_)
        ));
    }

    /// Content carrying the boundary is refused at assembly, through the composition.
    #[test]
    fn content_containing_the_boundary_is_refused_through_the_composition() {
        let mut fixture = Fixture::new();
        fixture.values = values(&[
            ("name", "Ada"),
            ("link", "https://x.test/--ironauth-boundary-01"),
        ]);
        assert!(matches!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::Mime(_)
        ));
    }

    /// A resolved template whose BODIES cannot be loaded fails, rather than sending an empty
    /// message.
    ///
    /// Distinct from having no template at all: resolution succeeded and the lookup then came
    /// back empty, which is the shape a deleted or half-migrated template row takes. Falling
    /// back to blank bodies would send a real recipient a real email with nothing in it.
    #[test]
    fn a_template_whose_bodies_are_missing_fails_rather_than_sending_blank() {
        let fixture = Fixture::new();
        let missing = |_: &str| None;
        let mut request = fixture.request("ada@example.test");
        request.bodies = &missing;
        assert_eq!(
            prepare_message(&request).unwrap_err(),
            PrepareError::NoTemplate
        );
    }

    /// A recipient over their budget is refused, with the instant a retry could succeed.
    #[test]
    fn a_rate_limited_recipient_is_refused_with_a_retry_instant() {
        let mut fixture = Fixture::new();
        let oldest = NOW - 30;
        fixture.recent_sends = vec![oldest, NOW - 20, NOW - 10];
        assert_eq!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::RateLimited {
                retry_after_epoch_seconds: oldest + 60
            },
        );
        // The control: one fewer prior send and the same request prepares, so the refusal is
        // the budget and not something else in the fixture.
        fixture.recent_sends = vec![NOW - 20, NOW - 10];
        assert!(prepare_message(&fixture.request("ada@example.test")).is_ok());
    }

    /// A rate limit is TEMPORARY and a suppression is PERMANENT, so they are distinct errors.
    ///
    /// Folding them together would have a caller either give up on a send that would work in a
    /// minute, or retry forever one that never will.
    #[test]
    fn a_rate_limit_is_not_reported_as_a_suppression() {
        let mut fixture = Fixture::new();
        fixture.recent_sends = vec![NOW - 30, NOW - 20, NOW - 10];
        let error = prepare_message(&fixture.request("ada@example.test")).unwrap_err();
        assert!(
            matches!(error, PrepareError::RateLimited { .. }),
            "expected a rate limit, got {error:?}"
        );
    }

    /// Suppression is checked BEFORE the rate limit, so a suppressed recipient never consumes
    /// budget.
    ///
    /// Otherwise an attacker could exhaust a victim's send budget using addresses that were
    /// already blocked, and the victim's legitimate mail would be refused as rate limited.
    #[test]
    fn a_suppressed_recipient_does_not_consume_rate_budget() {
        let mut fixture = Fixture::new();
        fixture.suppressed_addresses = ["ada@example.test".to_owned()].into_iter().collect();
        fixture.recent_sends = vec![NOW - 30, NOW - 20, NOW - 10];
        assert_eq!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::Blocked(BlockReason::AddressSuppressed),
            "the permanent reason must win, so the caller stops asking"
        );
    }

    /// The rate limit runs BEFORE rendering, so a refused send never puts user data through the
    /// renderer.
    ///
    /// The values here would FAIL the render (a missing placeholder). Getting the rate-limit
    /// error rather than a render error is what proves the ordering.
    #[test]
    fn a_rate_limited_send_is_refused_before_anything_is_rendered() {
        let mut fixture = Fixture::new();
        fixture.recent_sends = vec![NOW - 30, NOW - 20, NOW - 10];
        fixture.values = values(&[("name", "Ada")]);
        assert!(matches!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::RateLimited { .. }
        ));
    }

    #[test]
    fn no_template_at_any_level_is_its_own_error() {
        let mut fixture = Fixture::new();
        fixture.candidates = Vec::new();
        assert_eq!(
            prepare_message(&fixture.request("ada@example.test")).unwrap_err(),
            PrepareError::NoTemplate,
        );
    }

    /// The locale fallback is reported through the composition, so a caller can answer
    /// "why did this recipient get English?" without re-deriving it.
    #[test]
    fn a_locale_fallback_is_reported_on_the_prepared_message() {
        let mut fixture = Fixture::new();
        fixture.candidates = vec![candidate(TemplateLevel::Default, "en")];
        let prepared = prepare_message(&fixture.request("ada@example.test")).expect("prepared");
        assert_eq!(prepared.template_locale, Locale::new("en"));
        assert!(prepared.locale_fallback_applied);
    }

    /// A malformed address is blocked, not attempted.
    #[test]
    fn a_malformed_recipient_is_blocked() {
        let fixture = Fixture::new();
        assert_eq!(
            prepare_message(&fixture.request("not-an-address")).unwrap_err(),
            PrepareError::Blocked(BlockReason::AddressSuppressed),
        );
    }
}
