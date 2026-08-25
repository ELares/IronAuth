// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic HTTP message provider (issue #111).
//!
//! Issue #111 asks for "first-party SMTP and generic HTTP channels, plus adapters for SES,
//! `Postmark`, Resend, `SendGrid`, Mailgun and Twilio, behind ONE provider interface". This is
//! the generic HTTP one, and it is the shape every vendor adapter takes: POST the message
//! somewhere and turn the reply into the outcome vocabulary the failover driver walks.
//!
//! # Why it lives here and not in the store crate
//!
//! [`MessageProvider`] is defined in `ironauth-store` because the driver that walks it is, and
//! that crate is deliberately free of HTTP. Outbound HTTP in this codebase goes through the
//! SSRF-hardened [`ironauth_fetch::Fetcher`], which lives beside the webhook deliverer here.
//! A provider is IO; the seam is not.
//!
//! # The classification is the whole contract
//!
//! `message_http_channel::classify_status` already decides which HTTP statuses mean the
//! PROVIDER failed and which mean the MESSAGE was refused, and it is a reviewed, tested,
//! pure function. This adds only the part it cannot have: what a transport-level failure
//! means when there is no status at all.
//!
//! A blocked request, a timeout and a connection error are all
//! [`Outcome::ProviderUnavailable`], deliberately. The seam's own documentation says to choose
//! that when in doubt, and the reason applies exactly here: a needless retry at a second vendor
//! costs one message, while a misclassified provider outage silently drops mail that would have
//! been delivered. A `Blocked` result in particular says the URL failed SSRF policy, which is a
//! statement about the CONFIGURED ENDPOINT and never about the recipient.

use std::sync::Arc;

use ironauth_store::message_delivery::{MessageProvider, SendFuture};
use ironauth_store::message_failover::Outcome;
use ironauth_store::message_http_channel::classify_status;
use ironauth_store::message_prepare::PreparedMessage;

/// POSTs a prepared message to one configured endpoint.
pub struct HttpMessageProvider {
    name: String,
    endpoint: String,
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl std::fmt::Debug for HttpMessageProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The endpoint can carry a credential in its path or query for some vendors, so it is
        // NOT printed. The name is operator-chosen and safe.
        f.debug_struct("HttpMessageProvider")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl HttpMessageProvider {
    /// Build a provider that POSTs to `endpoint`, reporting itself as `name`.
    ///
    /// `name` appears in the delivery record and in failover reporting, so it should be the
    /// operator's word for this provider rather than a URL.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        fetcher: Arc<ironauth_fetch::Fetcher>,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            fetcher,
        }
    }

    /// The JSON body one send POSTs.
    ///
    /// Deliberately flat and vendor-neutral: an adapter for a named vendor overrides this
    /// wholesale, and a generic endpoint is somebody's own relay which can read what it likes.
    fn body(message: &PreparedMessage) -> String {
        serde_json::json!({
            "to": message.recipient,
            "subject": message.subject,
            "message_id": message.message_id,
            "boundary": message.boundary,
            "body": message.body,
        })
        .to_string()
    }
}

impl MessageProvider for HttpMessageProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(&'a self, message: &'a PreparedMessage) -> SendFuture<'a> {
        Box::pin(async move {
            let request = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::MessageDelivery,
                http::Method::POST,
                self.endpoint.clone(),
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(Self::body(message));

            match self.fetcher.fetch(request).await {
                Ok(response) => classify_status(Some(response.status().as_u16())),
                // No status at all. Every one of these is about the PROVIDER or the
                // deployment's own configuration, never about the recipient, so failing over
                // is right: another provider may well succeed with the same message.
                Err(_) => Outcome::ProviderUnavailable,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_store::message_template::{Locale, TemplateLevel};

    fn message() -> PreparedMessage {
        PreparedMessage {
            recipient: "ada@example.test".to_owned(),
            subject: "your code".to_owned(),
            message_id: "<m@example.test>".to_owned(),
            body: "--b\r\nhello\r\n--b--".to_owned(),
            boundary: "b".to_owned(),
            dedup_key: "k".to_owned(),
            template_level: TemplateLevel::Default,
            template_locale: Locale::new("en"),
            locale_fallback_applied: false,
        }
    }

    /// The posted body carries what a relay needs to send the message, and the assertion is on
    /// the DECODED json rather than on a substring: a body that happened to contain the right
    /// characters in the wrong structure would pass a `contains` check.
    #[test]
    fn the_body_carries_the_prepared_message() {
        let body: serde_json::Value =
            serde_json::from_str(&HttpMessageProvider::body(&message())).expect("valid json");
        assert_eq!(body["to"], "ada@example.test");
        assert_eq!(body["subject"], "your code");
        assert_eq!(body["message_id"], "<m@example.test>");
        assert_eq!(body["boundary"], "b");
        assert_eq!(body["body"], "--b\r\nhello\r\n--b--");
    }

    /// The endpoint may carry a credential in its path or query for some vendors, so `Debug`
    /// must not print it. A provider list is logged when failover reports which one was tried.
    #[test]
    fn debug_does_not_print_the_endpoint() {
        let provider = HttpMessageProvider::new(
            "relay",
            "https://user:secret@relay.example.test/send?key=abcdef",
            Arc::new(ironauth_fetch::Fetcher::for_tests(
                ironauth_fetch::FetchLimits::default(),
            )),
        );
        let rendered = format!("{provider:?}");
        assert!(
            rendered.contains("relay"),
            "the operator's name is safe to show"
        );
        assert!(
            !rendered.contains("secret") && !rendered.contains("abcdef"),
            "the endpoint can carry a credential and must not be printed: {rendered}"
        );
    }

    /// The provider reports the operator's name, which is what lands in the delivery record and
    /// in failover reporting.
    #[test]
    fn the_provider_reports_its_configured_name() {
        let provider = HttpMessageProvider::new(
            "postmark",
            "https://relay.example.test/send",
            Arc::new(ironauth_fetch::Fetcher::for_tests(
                ironauth_fetch::FetchLimits::default(),
            )),
        );
        assert_eq!(MessageProvider::name(&provider), "postmark");
    }
}
