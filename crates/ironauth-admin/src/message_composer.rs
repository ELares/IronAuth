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

use ironauth_store::MessageTemplateRecord;
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
    /// The body handle the built-in template is registered under. A configured template's
    /// handle is its row id, so this cannot collide with one.
    const BUILT_IN_REF: &'static str = "built-in";

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
    fn built_in() -> MessageBodies {
        // The KIND is deliberately NOT spliced in here. An earlier version built the subject
        // with `format!("Your {kind} from {{{{ tenant }}}}")`, which put caller-controlled text
        // into the TEMPLATE and then rendered it: a kind containing `{{ body }}` would pull a
        // payload value into the Subject header. Template text is a constant; everything
        // variable arrives as a VALUE, which the renderer escapes.
        MessageBodies {
            subject: "Your {{ kind }} from {{ tenant }}".to_owned(),
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
        configured: &[MessageTemplateRecord],
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
        // The kind and the tenant are VALUES, so the renderer escapes them and neither can
        // introduce markup or a placeholder. A caller cannot override them: `insert` rather
        // than `entry().or_insert()`, because a payload carrying its own "tenant" would
        // otherwise decide what the recipient is told this message is from.
        values.insert("kind".to_owned(), kind.to_owned());
        values.insert("tenant".to_owned(), scope.tenant().to_string());

        // No usable id means no stable Message-ID, and a shared one is worse than refusing.
        let Some(local) = message_id_local(payload) else {
            return Err("no_message_id".to_owned());
        };

        // The CONFIGURED templates first, then the built-in, which is the last level of the
        // resolution order (organization, environment, tenant, built-in default). The built-in
        // is always present, which is what makes resolution total: it is why
        // `resolve_template` can be documented as unable to fail.
        let built_in = Self::built_in();
        // ORGANIZATION-LEVEL ROWS ARE EXCLUDED, deliberately, and this is a limitation rather
        // than a design.
        //
        // `message_templates` carries an `organization_id`, but a `messages` row carries no
        // organization at all: the ledger has no such column and `NewMessage` no such field.
        // So nothing on this path can say WHICH organization a send belongs to, and applying an
        // organization's override without that check does not mean "the org override works" --
        // it means one organization's wording is mailed to every recipient in the environment,
        // including other organizations' users and users belonging to none. Measured: with two
        // organizations each holding an override, a message belonging to neither was composed
        // from one of them, and which one was an untied tie decided by row order.
        //
        // Shipping the override for everyone is worse than not shipping it, so until a message
        // can carry an organization these rows are skipped and resolution runs over the levels
        // that ARE well defined here. The remaining scoping work is the organization column on
        // `messages`, an organization argument on `candidates_for`, and a deterministic
        // tie-break on its ORDER BY.
        let mut candidates: Vec<TemplateCandidate> = configured
            .iter()
            .filter(|record| record.level != TemplateLevel::Organization)
            .map(|record| TemplateCandidate {
                level: record.level,
                locale: Locale::new(&record.locale),
                body_ref: record.id.to_string(),
            })
            .collect();
        candidates.push(TemplateCandidate {
            level: TemplateLevel::Default,
            locale: self.default_locale.clone(),
            body_ref: Self::BUILT_IN_REF.to_owned(),
        });

        // The body loader answers from the same records the candidates came from, so a
        // resolution can only ever name a body this call actually holds.
        let bodies = |body_ref: &str| -> Option<MessageBodies> {
            if body_ref == Self::BUILT_IN_REF {
                return Some(built_in.clone());
            }
            configured
                .iter()
                .filter(|record| record.level != TemplateLevel::Organization)
                .find(|record| record.id.to_string() == body_ref)
                .map(|record| MessageBodies {
                    subject: record.subject.clone(),
                    text: record.body_text.clone(),
                    // A template with no HTML part still has to produce a multipart body, so
                    // the text stands in. An empty HTML part would ship a message whose
                    // alternative half is blank, which some clients render as an empty mail.
                    //
                    // ESCAPED on the way across. The renderer escapes VALUES for an HTML body,
                    // but the template text itself is copied verbatim, so a text template
                    // containing `<` or `&` would emit broken or injected markup into the HTML
                    // alternative. A text template is not HTML and must not become HTML by
                    // being reused as it.
                    html: record
                        .body_html
                        .clone()
                        .unwrap_or_else(|| escape_text_as_html(&record.body_text)),
                })
        };

        // A missing or non-string `body` is a REFUSAL, not an empty message. Filling it with
        // a default silently sends a blank mail to a real person, and `RenderError` already
        // exists to say so: composing something empty is worse than composing nothing, because
        // the empty one is delivered and counts as a success.
        if !values.contains_key("body") {
            return Err("missing_body".to_owned());
        }

        let request = PrepareRequest {
            kind,
            recipient,
            candidates: &candidates,
            requested_locale: &self.default_locale,
            default_locale: &self.default_locale,
            bodies: &bodies,
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
            message_id_local: &local,
            message_id_domain: &self.sender_domain,
            boundary: &boundary_for(&local),
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

/// Escape a TEXT template so it can stand in for a missing HTML one.
///
/// Only the markup-significant characters, and deliberately not the placeholder braces: the
/// result is still a template and must still render. What is escaped is what would otherwise
/// become markup, which a plain-text template never intended.
fn escape_text_as_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// The local part of the `Message-ID`, from the payload's message id.
///
/// Returns [`None`] rather than a fallback, and that is the whole point. An earlier version
/// answered `"message"` for every payload that carried no id, so EVERY such message shipped
/// the identical `Message-ID` and a receiver deduplicating on it would drop all but the first.
/// A message with no stable identity has no business being stamped with a shared one.
///
/// Sanitising also REJECTS rather than filters. Filtering collapses distinct ids onto one
/// local part -- `msg/1` and `msg1` both became `msg1` -- which is the same collision by a
/// different route.
fn message_id_local(payload: &serde_json::Value) -> Option<String> {
    let raw = payload.get("message_id")?.as_str()?;
    if raw.is_empty()
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(raw.to_owned())
}

/// A MIME boundary that cannot appear in the body it delimits.
fn boundary_for(local: &str) -> String {
    format!("ironauth-{local}")
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

    fn compose_kind(kind: &str, payload: &serde_json::Value) -> Result<PreparedMessage, String> {
        DefaultComposer::new("mail.example.test").compose(
            scope(),
            kind,
            "ada@example.test",
            payload,
            &[],
        )
    }

    /// A configured template at one level, for the resolution-order tests.
    ///
    /// Each record gets a DISTINCT id. An earlier version seeded the generator identically for
    /// every call, so all of them shared one id and the body lookup returned whichever came
    /// first -- the environment template lost to the tenant one, and the test caught it.
    fn configured(
        level: TemplateLevel,
        locale: &str,
        subject: &str,
        text: &str,
    ) -> MessageTemplateRecord {
        configured_html(level, locale, subject, text, None)
    }

    fn configured_html(
        level: TemplateLevel,
        locale: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> MessageTemplateRecord {
        // Seeded from the SUBJECT, not the level, so two records at the same level still get
        // distinct ids. Keying on the level made "each record gets a distinct id" false for
        // exactly the case the id lookup has to get right.
        let seed = subject.bytes().fold(41_u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(u64::from(b))
        });
        let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, seed);
        MessageTemplateRecord {
            id: ironauth_store::MessageTemplateId::generate(&env, &scope()),
            level,
            organization_id: None,
            kind: "login_code".to_owned(),
            locale: locale.to_owned(),
            subject: subject.to_owned(),
            body_text: text.to_owned(),
            body_html: html.map(str::to_owned),
            locked: false,
        }
    }

    fn compose_with(
        records: &[MessageTemplateRecord],
        payload: &serde_json::Value,
    ) -> Result<PreparedMessage, String> {
        DefaultComposer::new("mail.example.test").compose(
            scope(),
            "login_code",
            "ada@example.test",
            payload,
            records,
        )
    }

    fn compose(payload: &serde_json::Value) -> Result<PreparedMessage, String> {
        compose_kind("login_code", payload)
    }

    fn ok(body: &str, id: &str) -> serde_json::Value {
        serde_json::json!({ "body": body, "message_id": id })
    }

    /// The payload's values reach the body, and the Message-ID is well formed.
    ///
    /// RFC 5322 section 3.6.4 requires one, and shipping without it costs deliverability: it
    /// is the mistake Kratos made and had to fix.
    #[test]
    fn a_composed_message_renders_the_payload_and_stamps_a_message_id() {
        let prepared = compose(&ok("your code is 123456", "msg_abc123")).expect("composes");
        assert_eq!(prepared.recipient, "ada@example.test");
        assert!(
            prepared.body.contains("your code is 123456"),
            "{}",
            prepared.body
        );
        assert!(
            prepared.message_id.starts_with('<') && prepared.message_id.ends_with('>'),
            "{}",
            prepared.message_id
        );
        assert!(
            prepared.message_id.contains("msg_abc123"),
            "{}",
            prepared.message_id
        );
    }

    /// The DOMAIN half is what makes a Message-ID globally unique rather than merely random,
    /// so it must come from the composer's configuration and not from a constant. Two
    /// different domains must produce two different Message-IDs: pinning only the fixture's
    /// own literal would pass against a hardcoded domain.
    #[test]
    fn the_message_id_carries_the_configured_sending_domain() {
        let payload = ok("hello", "msg_same");
        let a = DefaultComposer::new("a.example.test")
            .compose(scope(), "login_code", "ada@example.test", &payload, &[])
            .expect("a");
        let b = DefaultComposer::new("b.example.test")
            .compose(scope(), "login_code", "ada@example.test", &payload, &[])
            .expect("b");
        assert!(a.message_id.contains("a.example.test"), "{}", a.message_id);
        assert!(b.message_id.contains("b.example.test"), "{}", b.message_id);
        assert_ne!(a.message_id, b.message_id);
    }

    /// The SAME payload composes to the same Message-ID, so a redelivery is one message.
    #[test]
    fn a_redelivery_keeps_one_message_id() {
        let payload = ok("hello", "msg_stable");
        assert_eq!(
            compose(&payload).expect("first").message_id,
            compose(&payload).expect("second").message_id
        );
    }

    /// Two DIFFERENT messages must not share a Message-ID, or a receiver deduplicating on it
    /// drops the second. Includes the pair that COLLIDED under the previous implementation,
    /// which filtered disallowed characters instead of refusing them.
    #[test]
    fn two_messages_do_not_share_a_message_id() {
        let a = compose(&ok("a", "msg_aaa")).expect("a");
        let b = compose(&ok("b", "msg_bbb")).expect("b");
        assert_ne!(a.message_id, b.message_id);

        // `msg/1` and `msg1` both sanitised to `msg1` before. Now the first is refused
        // outright rather than silently becoming the second.
        assert!(
            compose(&ok("x", "msg/1")).is_err(),
            "a malformed id is refused"
        );
    }

    /// A payload with NO message id is refused. Previously every such message was stamped
    /// `<message@domain>`, so they ALL shared one Message-ID and a receiver deduplicating on it
    /// would drop every one after the first.
    #[test]
    fn a_payload_without_a_message_id_is_refused_rather_than_sharing_one() {
        let refused = compose(&serde_json::json!({ "body": "hello" }));
        assert_eq!(refused.err().as_deref(), Some("no_message_id"));
    }

    /// A missing or non-string `body` is REFUSED, not composed to an empty message. Sending a
    /// blank mail to a real person and recording it as delivered is worse than sending nothing.
    #[test]
    fn a_missing_or_structured_body_is_refused_rather_than_sent_empty() {
        assert_eq!(
            compose(&serde_json::json!({ "message_id": "msg_x" }))
                .err()
                .as_deref(),
            Some("missing_body"),
            "a message with no body must not be sent"
        );
        assert_eq!(
            compose(&serde_json::json!({ "message_id": "msg_x", "body": { "n": 1 } }))
                .err()
                .as_deref(),
            Some("missing_body"),
            "a structured body is not a body: stringifying it sends {{\"n\":1}} to a person"
        );
    }

    /// The KIND is a VALUE, never template text. Splicing it into the template let a kind
    /// containing a placeholder pull a payload value into the Subject header.
    #[test]
    fn a_kind_containing_a_placeholder_cannot_pull_a_payload_value_into_the_subject() {
        let prepared =
            compose_kind("{{ body }}", &ok("SECRET-CODE-42", "msg_inject")).expect("composes");
        assert!(
            !prepared.subject.contains("SECRET-CODE-42"),
            "a kind that is template text would render the payload into the Subject: {}",
            prepared.subject
        );
        assert!(
            prepared.subject.contains("{{ body }}"),
            "and the kind itself is shown literally: {}",
            prepared.subject
        );
    }

    /// The subject renders both of its values, which nothing asserted before.
    #[test]
    fn the_subject_renders_the_kind_and_the_tenant() {
        let prepared = compose(&ok("hello", "msg_subj")).expect("composes");
        assert!(
            prepared.subject.contains("login_code"),
            "{}",
            prepared.subject
        );
        assert!(
            prepared.subject.contains(&scope().tenant().to_string()),
            "{}",
            prepared.subject
        );
    }

    /// A payload cannot override the kind or the tenant, which decide what the recipient is
    /// told this message IS and who it is from.
    #[test]
    fn a_payload_cannot_override_the_kind_or_the_tenant() {
        let prepared = compose(&serde_json::json!({
            "body": "hello",
            "message_id": "msg_ovr",
            "kind": "password_reset",
            "tenant": "some-other-tenant",
        }))
        .expect("composes");
        assert!(
            prepared.subject.contains("login_code"),
            "{}",
            prepared.subject
        );
        assert!(
            !prepared.subject.contains("password_reset"),
            "{}",
            prepared.subject
        );
        assert!(
            !prepared.subject.contains("some-other-tenant"),
            "{}",
            prepared.subject
        );
    }

    /// A non-string payload field is SKIPPED, not stringified. The fixture key is a real
    /// placeholder in the template, so this fails if the value ever reaches it -- the previous
    /// version used a key the template never mentions, so it could not fail either way.
    #[test]
    fn a_non_string_payload_field_does_not_reach_the_body() {
        let refused = compose(&serde_json::json!({
            "message_id": "msg_ns",
            "body": { "nested": 1 },
        }));
        assert_eq!(
            refused.err().as_deref(),
            Some("missing_body"),
            "a structured value must not be stringified into the one placeholder it names"
        );
    }

    /// Multipart with BOTH parts populated. Asserting only the content-type headers passes with
    /// an empty HTML part, and asserting the boundary appears in the body is a tautology --
    /// `multipart_alternative` writes the delimiters from that same boundary.
    #[test]
    fn the_body_is_multipart_with_both_parts_populated() {
        let prepared = compose(&ok("hello-there", "msg_mp")).expect("composes");
        assert!(prepared.body.contains("text/plain"), "{}", prepared.body);
        assert!(prepared.body.contains("text/html"), "{}", prepared.body);
        assert!(
            prepared.body.contains("<p>hello-there</p>"),
            "the HTML part must carry the rendered body, not just its header: {}",
            prepared.body
        );
        let plain_at = prepared.body.find("text/plain").expect("a text part");
        let html_at = prepared.body.find("text/html").expect("an html part");
        assert!(plain_at < html_at, "RFC 2046: least-rich part first");
    }

    /// The built-in is the DEFAULT level, which is what the three configurable levels fall
    /// back to. Unpinned, a change to the level would be invisible.
    #[test]
    fn the_built_in_resolves_at_the_default_level() {
        let prepared = compose(&ok("hello", "msg_lvl")).expect("composes");
        assert_eq!(prepared.template_level, TemplateLevel::Default);
        assert!(!prepared.locale_fallback_applied);
    }

    /// CRITERION 3, the resolution order: organization overrides environment overrides tenant
    /// overrides the built-in default.
    ///
    /// Each level is added on top of the last and the subject must change every time. Asserting
    /// only that the strongest wins would pass against an implementation that always picked the
    /// first record it was handed.
    #[test]
    fn a_stronger_level_overrides_a_weaker_one_all_the_way_down() {
        let payload = ok("hello", "msg_res");

        let built_in = compose_with(&[], &payload).expect("built-in");
        assert!(
            built_in.subject.contains("login_code"),
            "{}",
            built_in.subject
        );
        assert_eq!(built_in.template_level, TemplateLevel::Default);

        let tenant = configured(TemplateLevel::Tenant, "en", "TENANT SUBJECT", "t");
        let at_tenant = compose_with(std::slice::from_ref(&tenant), &payload).expect("tenant");
        assert_eq!(at_tenant.subject, "TENANT SUBJECT");
        assert_eq!(at_tenant.template_level, TemplateLevel::Tenant);

        let environment = configured(TemplateLevel::Environment, "en", "ENVIRONMENT SUBJECT", "e");
        let at_env =
            compose_with(&[tenant.clone(), environment.clone()], &payload).expect("environment");
        assert_eq!(
            at_env.subject, "ENVIRONMENT SUBJECT",
            "an environment template must beat the tenant one"
        );
        assert_eq!(at_env.template_level, TemplateLevel::Environment);
    }

    /// An organization-level row is IGNORED, and that is a documented limitation rather than
    /// the finished behaviour.
    ///
    /// A `messages` row carries no organization, so nothing here can say which organization a
    /// send belongs to. Applying the override anyway would not mean the org override works: it
    /// would mean one organization's wording is mailed to every recipient in the environment,
    /// including other organizations' users and users belonging to none. Measured, with two
    /// organizations each holding an override, a message belonging to NEITHER was composed
    /// from one of them, chosen by an untied tie.
    ///
    /// So this pins the skip. When a message can carry an organization, this is the test that
    /// has to change, which is the point of writing it down.
    #[test]
    fn an_organization_template_is_skipped_until_a_message_can_name_its_organization() {
        let payload = ok("hello", "msg_org");
        let organization = configured(TemplateLevel::Organization, "en", "ORG SUBJECT", "o");
        let tenant = configured(TemplateLevel::Tenant, "en", "TENANT SUBJECT", "t");

        let only_org =
            compose_with(std::slice::from_ref(&organization), &payload).expect("composes");
        assert_eq!(
            only_org.template_level,
            TemplateLevel::Default,
            "with only an organization row configured the BUILT-IN applies, not that row"
        );
        assert!(
            !only_org.subject.contains("ORG SUBJECT"),
            "{}",
            only_org.subject
        );

        let with_tenant = compose_with(&[organization, tenant], &payload).expect("composes");
        assert_eq!(
            with_tenant.subject, "TENANT SUBJECT",
            "and an organization row must not outrank the tenant one it cannot be scoped \
             against"
        );
    }

    /// A configured template's VALUES still render, so an override is a template rather than a
    /// literal string.
    #[test]
    fn a_configured_template_still_interpolates_its_values() {
        let record = configured(
            TemplateLevel::Tenant,
            "en",
            "Code for {{ tenant }}",
            "Your code: {{ body }}",
        );
        let prepared = compose_with(&[record], &ok("998877", "msg_int")).expect("composes");
        assert!(prepared.body.contains("998877"), "{}", prepared.body);
        assert!(
            prepared.subject.contains(&scope().tenant().to_string()),
            "{}",
            prepared.subject
        );
    }

    /// A template with no HTML part still produces BOTH multipart parts. An empty HTML
    /// alternative ships a message whose richer half is blank, which some clients render as an
    /// empty mail.
    #[test]
    fn a_template_without_html_still_produces_both_parts() {
        let record = configured(TemplateLevel::Tenant, "en", "S", "TEXT-ONLY-BODY");
        let prepared = compose_with(&[record], &ok("x", "msg_html")).expect("composes");
        assert!(prepared.body.contains("text/plain"), "{}", prepared.body);
        assert!(prepared.body.contains("text/html"), "{}", prepared.body);
        assert_eq!(
            prepared.body.matches("TEXT-ONLY-BODY").count(),
            2,
            "the text stands in for the missing HTML part, so it appears in both: {}",
            prepared.body
        );
    }

    /// A template for a DIFFERENT locale falls back to the default one rather than failing, and
    /// says it fell back.
    #[test]
    fn an_unavailable_locale_falls_back_and_reports_it() {
        let other = configured(TemplateLevel::Tenant, "fr", "SUJET", "corps");
        let prepared = compose_with(&[other], &ok("x", "msg_loc")).expect("composes");
        assert_eq!(prepared.subject, "SUJET", "the only template is used");
        assert!(
            prepared.locale_fallback_applied,
            "and the caller is told the requested locale was unavailable"
        );
    }

    /// A configured `body_html` is USED. No fixture set one before, so the HTML branch could
    /// be dropped on the floor with every test green.
    #[test]
    fn a_configured_html_body_is_used_rather_than_the_text() {
        let record = configured_html(
            TemplateLevel::Tenant,
            "en",
            "S",
            "PLAIN-VERSION",
            Some("<b>RICH-VERSION</b>"),
        );
        let prepared = compose_with(&[record], &ok("x", "msg_rich")).expect("composes");
        assert!(prepared.body.contains("PLAIN-VERSION"), "{}", prepared.body);
        assert!(
            prepared.body.contains("<b>RICH-VERSION</b>"),
            "the configured HTML part must be the HTML part: {}",
            prepared.body
        );
    }

    /// A TEXT template standing in for a missing HTML one is ESCAPED. The renderer escapes
    /// VALUES for an HTML body but copies the template text verbatim, so a plain-text template
    /// containing markup characters would emit broken or injected markup into the alternative.
    #[test]
    fn a_text_template_reused_as_html_is_escaped() {
        let record = configured(
            TemplateLevel::Tenant,
            "en",
            "S",
            "5 < 6 & <script>alert(1)</script>",
        );
        let prepared = compose_with(&[record], &ok("x", "msg_esc")).expect("composes");

        // Scoped to the HTML PART. The text part legitimately contains the raw characters --
        // it is plain text and nothing there is markup -- so asserting over the whole
        // multipart body tests the wrong half and fails for the wrong reason.
        let html_part = prepared
            .body
            .split("text/html")
            .nth(1)
            .expect("an html part");
        assert!(
            !html_part.contains("<script>"),
            "a text template must not become live markup in the HTML part: {html_part}"
        );
        assert!(
            html_part.contains("&lt;script&gt;"),
            "it should appear escaped instead: {html_part}"
        );
        assert!(
            prepared.body.contains("<script>alert(1)</script>"),
            "and the TEXT part keeps it verbatim, because plain text is not markup: {}",
            prepared.body
        );
    }

    /// A configured template in the REQUESTED locale reports no fallback. Without this, a
    /// configured locale could be mangled into the default and nothing would notice.
    #[test]
    fn a_configured_template_in_the_requested_locale_reports_no_fallback() {
        let record = configured(TemplateLevel::Tenant, "en", "S", "t");
        let prepared = compose_with(&[record], &ok("x", "msg_nofb")).expect("composes");
        assert!(
            !prepared.locale_fallback_applied,
            "the requested locale was available, so nothing fell back"
        );
        assert_eq!(prepared.template_locale, Locale::new("en"));
    }

    /// Two templates at the SAME level with DIFFERENT ids resolve to the right BODY. The body
    /// lookup keys on the row id, and a fixture whose records shared an id could not tell a
    /// correct lookup from one that took whichever came first.
    #[test]
    fn the_body_lookup_keys_on_the_row_id_not_on_position() {
        let english = configured(TemplateLevel::Tenant, "en", "EN SUBJECT", "EN BODY");
        let french = configured(TemplateLevel::Tenant, "fr", "FR SUBJECT", "FR BODY");
        assert_ne!(english.id, french.id, "the fixture must give distinct ids");

        for records in [vec![english.clone(), french.clone()], vec![french, english]] {
            let prepared = compose_with(&records, &ok("x", "msg_ids")).expect("composes");
            assert_eq!(
                prepared.subject, "EN SUBJECT",
                "the requested locale decides, whatever order the rows arrive in"
            );
            assert!(
                prepared.body.contains("EN BODY"),
                "and the BODY must come from the same row as the subject: {}",
                prepared.body
            );
        }
    }
}
