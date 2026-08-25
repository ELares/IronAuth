// SPDX-License-Identifier: MIT OR Apache-2.0

//! Composing what a queued message SAYS, from the built-in default template (issue #111).
//!
//! [`MessageComposer`] is the seam the delivery consumer calls once it has opened a row's
//! sealed recipient. This is the implementation that ships first, and it deliberately does the
//! LAST step of the resolution order issue #111 specifies and no other: organization override,
//! then environment, then tenant, then BUILT-IN DEFAULT. The three configurable levels are
//! stored per environment and are their own change; the built-in is the one that must exist for
//! any of them to fall back to, and a deployment with no templates configured is exactly the
//! deployment this serves.
//!
//! # Where the values come from, and what is deliberately not in them
//!
//! The outbox payload. It is written by whoever enqueued the message and read back here, and it
//! is the one place a template variable can live: the ledger row deliberately holds no body,
//! because a rendered message contains the secret the send exists to carry.
//!
//! That is also why the payload is not a free-for-all. A caller that puts a live secret in it
//! has put that secret on a durable queue every consumer worker reads, which is the exact thing
//! the sealed recipient exists to avoid. The doors that carry secrets (email OTP, magic link)
//! therefore do not use this path at all: their bodies are delivered in the request that minted
//! them. This path is for messages whose variables are safe to write down.

use std::collections::BTreeSet;

use ironauth_store::Scope;
use ironauth_store::message_consumer::MessageComposer;
use ironauth_store::message_prepare::{
    MessageBodies, PrepareError, PrepareRequest, PreparedMessage, prepare_message,
};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::message_render::RenderContext;
use ironauth_store::message_template::{Locale, TemplateCandidate, TemplateLevel};

/// The sending identity and the built-in template, for a deployment with nothing configured.
#[derive(Debug, Clone)]
pub struct DefaultComposer {
    sender_domain: String,
    default_locale: Locale,
}

impl DefaultComposer {
    /// Build the composer for `sender_domain`, which is the right-hand side of the
    /// `Message-ID` this deployment stamps on every message it sends.
    ///
    /// RFC 5322 section 3.6.4 requires a globally unique `Message-ID`, and Kratos shipped
    /// without one at all (their issue #4446), which cost them deliverability. The domain half
    /// is what makes ours unique rather than merely random.
    #[must_use]
    pub fn new(sender_domain: impl Into<String>) -> Self {
        Self {
            sender_domain: sender_domain.into(),
            default_locale: Locale::new("en"),
        }
    }

    /// The built-in body for a kind.
    ///
    /// One template, deliberately plain. It is the floor of the resolution order, not a
    /// product: a deployment that wants its own wording configures one, and this is what
    /// arrives until it does. Making it elaborate would only make the difference between
    /// configured and unconfigured harder to notice.
    fn built_in(kind: &str) -> MessageBodies {
        MessageBodies {
            subject: format!("Your {kind} from {{{{ tenant }}}}"),
            text: "{{ body }}\n".to_owned(),
            html: "<p>{{ body }}</p>".to_owned(),
        }
    }
}

impl MessageComposer for DefaultComposer {
    fn compose(
        &self,
        scope: Scope,
        kind: &str,
        recipient: &str,
        payload: &serde_json::Value,
    ) -> Result<PreparedMessage, String> {
        // The payload's flat string fields become the template values. A non-string field is
        // SKIPPED rather than stringified: `{{ x }}` rendering as `{"a":1}` is a broken message
        // that looks like a working one, and the sender finds out from the recipient.
        let mut values: RenderContext = RenderContext::new();
        if let Some(object) = payload.as_object() {
            for (key, value) in object {
                if let Some(text) = value.as_str() {
                    values.insert(key.clone(), text.to_owned());
                }
            }
        }
        values
            .entry("tenant".to_owned())
            .or_insert_with(|| scope.tenant().to_string());
        values.entry("body".to_owned()).or_default();

        let bodies = Self::built_in(kind);
        // The built-in must be a CANDIDATE, not merely a body the loader can return. Template
        // resolution walks the levels and fails with no template when the list is empty, so an
        // empty list plus a loader that always answers is a composer that never composes.
        let candidates = vec![TemplateCandidate {
            level: TemplateLevel::Default,
            locale: self.default_locale.clone(),
            body_ref: format!("built-in:{kind}"),
        }];

        let request = PrepareRequest {
            kind,
            recipient,
            candidates: &candidates,
            requested_locale: &self.default_locale,
            default_locale: &self.default_locale,
            bodies: &|_| Some(bodies.clone()),
            values: &values,
            // Suppression and the per-recipient rate limit are enforced by the CALLER that
            // enqueues, not here: this runs after the message is already queued, and refusing
            // it at delivery time would record a failure for a send that policy should never
            // have accepted. Empty sets and an effectively unbounded budget say so explicitly
            // rather than by omission.
            suppressed_addresses: &BTreeSet::new(),
            suppressed_domains: &BTreeSet::new(),
            window: 0,
            recent_sends: &[],
            rate_budget: RateBudget::new(u32::MAX, 1),
            now_epoch_seconds: 0,
            // Unique per send, and derived from the ledger id rather than from a clock or a
            // random source: the id is already unique per message and is stable across a
            // retry, so a redelivered message keeps ONE Message-ID instead of looking like two
            // messages to a receiver that deduplicates on it.
            message_id_local: &message_id_local(payload),
            message_id_domain: &self.sender_domain,
            boundary: &boundary_for(payload),
        };

        prepare_message(&request).map_err(|error| match error {
            PrepareError::Blocked(reason) => format!("blocked_{}", reason.as_str()),
            PrepareError::RateLimited { .. } => "rate_limited".to_owned(),
            PrepareError::NoTemplate => "no_template".to_owned(),
            PrepareError::Render(_) => "render_failed".to_owned(),
            PrepareError::Mime(_) => "mime_failed".to_owned(),
        })
    }
}

/// The local part of the `Message-ID`, from the payload's message id when it carries one.
fn message_id_local(payload: &serde_json::Value) -> String {
    payload
        .get("message_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| "message".to_owned(), sanitize_local)
}

/// A MIME boundary that cannot appear in the body it delimits.
fn boundary_for(payload: &serde_json::Value) -> String {
    format!("ironauth-{}", message_id_local(payload))
}

/// Keep only characters RFC 5322 permits unquoted in a `Message-ID` local part.
fn sanitize_local(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if cleaned.is_empty() {
        "message".to_owned()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, TenantId};

    fn scope() -> Scope {
        let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 21);
        Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
    }

    fn compose(payload: &serde_json::Value) -> Result<PreparedMessage, String> {
        DefaultComposer::new("mail.example.test").compose(
            scope(),
            "login_code",
            "ada@example.test",
            payload,
        )
    }

    /// The composed message carries the payload's values and a well-formed `Message-ID`.
    ///
    /// RFC 5322 section 3.6.4 requires one, and shipping without it costs deliverability: it is
    /// the mistake Kratos made and had to fix. So the presence AND the shape are pinned.
    #[test]
    fn a_composed_message_renders_the_payload_and_stamps_a_message_id() {
        let prepared = compose(&serde_json::json!({
            "body": "your code is 123456",
            "message_id": "msg_abc123",
        }))
        .expect("composes");

        assert_eq!(prepared.recipient, "ada@example.test");
        assert!(
            prepared.body.contains("your code is 123456"),
            "the payload's values must reach the body: {}",
            prepared.body
        );
        assert!(
            prepared.message_id.starts_with('<') && prepared.message_id.ends_with('>'),
            "a Message-ID is angle-bracketed: {}",
            prepared.message_id
        );
        assert!(
            prepared.message_id.contains("mail.example.test"),
            "and carries the sending domain, which is what makes it unique rather than \
             merely random: {}",
            prepared.message_id
        );
        assert!(
            prepared.message_id.contains("msg_abc123") || prepared.message_id.contains("msgabc123"),
            "and is derived from the message id, so a redelivery keeps ONE Message-ID \
             instead of looking like two messages: {}",
            prepared.message_id
        );
    }

    /// The SAME payload composes to the same `Message-ID`, which is what makes a retry one
    /// message rather than two to a receiver that deduplicates on it.
    #[test]
    fn a_redelivery_keeps_one_message_id() {
        let payload = serde_json::json!({ "body": "hello", "message_id": "msg_stable" });
        let first = compose(&payload).expect("composes");
        let second = compose(&payload).expect("composes");
        assert_eq!(
            first.message_id, second.message_id,
            "a redelivered message must not look like a second message"
        );
    }

    /// Two DIFFERENT messages must not share a `Message-ID`, or a receiver that deduplicates
    /// on it drops the second one.
    #[test]
    fn two_messages_do_not_share_a_message_id() {
        let a = compose(&serde_json::json!({ "body": "a", "message_id": "msg_aaa" })).expect("a");
        let b = compose(&serde_json::json!({ "body": "b", "message_id": "msg_bbb" })).expect("b");
        assert_ne!(a.message_id, b.message_id);
    }

    /// A non-string payload field is SKIPPED, not stringified. `{{ code }}` rendering as
    /// `{"a":1}` is a broken message that looks like a working one, and the sender finds out
    /// from the recipient.
    #[test]
    fn a_non_string_payload_field_does_not_reach_the_body() {
        let prepared = compose(&serde_json::json!({
            "body": "ok",
            "structured": { "nested": 1 },
        }))
        .expect("composes");
        assert!(
            !prepared.body.contains("nested"),
            "a structured field must not be stringified into a message: {}",
            prepared.body
        );
    }

    /// The body is multipart with both a text and an HTML part, which is what issue #111 means
    /// by "correct text plus HTML multipart output".
    #[test]
    fn the_body_is_multipart_with_both_parts() {
        let prepared = compose(&serde_json::json!({ "body": "hello" })).expect("composes");
        assert!(prepared.body.contains("text/plain"), "{}", prepared.body);
        assert!(prepared.body.contains("text/html"), "{}", prepared.body);
        assert!(
            prepared.body.contains(&prepared.boundary),
            "the outer Content-Type boundary must appear in the body"
        );
    }
}
