// SPDX-License-Identifier: MIT OR Apache-2.0

//! The emulator's message capture sink (issue #121, criterion 5).
//!
//! # Why the sink is a SEPARATE listener, not a route on the server
//!
//! This endpoint hands out live one-time codes in plaintext. That is the entire point in
//! dev, and it is catastrophic anywhere else, so the design goal is that it cannot exist in
//! production even by accident.
//!
//! Mounting it on the OIDC router would make that a matter of a conditional staying correct
//! forever: one refactor that moves a route registration outside its `if`, and a production
//! deployment is serving OTP codes. Running it on its own loopback listener, started only by
//! `ironauth dev`, means the production router has no such route to leak. The guarantee is
//! structural rather than a flag nobody re-reads.
//!
//! # What is captured, and what that means
//!
//! Everything the delivery seams are handed, INCLUDING the codes. A sink that redacted them
//! would be useless for the thing this exists for: letting CI assert a complete login
//! without a mail server. So the sink is a plaintext secret store by design, which is the
//! other half of why it is loopback-only and dev-only.

use std::collections::VecDeque;
use std::sync::Mutex;

use ironauth_oidc::{
    EmailOtpMessage, MagicLinkMessage, SmsOtpMessage, SmsSender, VerificationPurpose,
    VerificationSender,
};
use ironauth_store::Scope;

/// How many messages are kept.
///
/// Bounded because the emulator is long-lived in a test session and an unbounded log of
/// every code ever sent is a slow leak. The oldest are dropped, which is the right end to
/// lose: a test asserts against what it just triggered.
const CAPACITY: usize = 256;

/// One captured message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// `email` or `sms`.
    pub kind: &'static str,
    /// Who it was addressed to.
    pub recipient: String,
    /// The one-time code or link, in plaintext. See the module docs.
    pub body: String,
}

impl Captured {
    /// The JSON object for this message.
    ///
    /// Hand-rolled rather than derived, so the sink's wire shape is visible here and cannot
    /// change silently when a field is added to the struct for some other reason.
    fn to_json(&self) -> String {
        format!(
            "{{\"kind\":\"{}\",\"recipient\":{},\"body\":{}}}",
            self.kind,
            json_string(&self.recipient),
            json_string(&self.body)
        )
    }
}

/// Encode one JSON string, escaping what the grammar requires.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Control characters are not legal raw in a JSON string.
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The in-memory sink.
#[derive(Debug, Default)]
pub struct CaptureSink {
    messages: Mutex<VecDeque<Captured>>,
}

impl CaptureSink {
    /// Record one message, dropping the oldest when full.
    fn push(&self, captured: Captured) {
        let mut messages = self.messages.lock().expect("capture sink mutex");
        if messages.len() == CAPACITY {
            messages.pop_front();
        }
        // Through TRACING, never `println!`. Measured (#842): a `println!` here wedged the
        // entire server on the first delivery -- discovery, JWKS and the token endpoint all
        // stopped answering. This runs synchronously inside an async request handler, and
        // `println!` takes the process-wide stdout lock that the tracing writer also uses,
        // so a delivery could sit on it and take an executor worker down with it.
        //
        // `tracing` is the writer every other line in this process already goes through, and
        // it is built for exactly this call site. Instrumented proof of the diagnosis: an
        // `eprintln!` probe at the top of this function printed and the next statement never
        // did.
        //
        // Surfaced as well as stored, because the issue asks for both and a developer
        // watching the terminal should not have to curl to see the code they are waiting for.
        tracing::info!(
            kind = captured.kind,
            recipient = %captured.recipient,
            body = %captured.body,
            "ironauth dev: captured message"
        );
        messages.push_back(captured);
    }

    /// Every captured message, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Captured> {
        self.messages
            .lock()
            .expect("capture sink mutex")
            .iter()
            .cloned()
            .collect()
    }

    /// The sink's JSON body.
    #[must_use]
    pub fn to_json(&self) -> String {
        let items: Vec<String> = self.snapshot().iter().map(Captured::to_json).collect();
        format!("{{\"messages\":[{}]}}", items.join(","))
    }
}

impl VerificationSender for CaptureSink {
    fn send(&self, _scope: Scope, _purpose: VerificationPurpose, _recipient: &str) {
        // The generic notification carries no code, so there is nothing a test asserts
        // against. Deliberately not recorded: filling the bounded buffer with messages
        // nobody reads would evict the ones somebody does.
    }

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        self.push(Captured {
            kind: "email",
            recipient: message.recipient.to_owned(),
            body: message.code.to_owned(),
        });
    }

    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        self.push(Captured {
            kind: "email",
            recipient: message.recipient.to_owned(),
            body: message.link.to_owned(),
        });
    }
}

impl SmsSender for CaptureSink {
    fn send(&self, message: &SmsOtpMessage<'_>) {
        self.push(Captured {
            kind: "sms",
            recipient: message.recipient.to_owned(),
            body: message.code.to_owned(),
        });
    }
}

/// The HTTP response the sink listener returns.
#[must_use]
pub fn sink_response(sink: &CaptureSink) -> String {
    let body = sink.to_json();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use ironauth_store::EmailFactorPurpose;

    use super::*;

    fn sink() -> CaptureSink {
        CaptureSink::default()
    }

    #[test]
    fn an_email_code_is_captured_in_plaintext() {
        let sink = sink();
        sink.push(Captured {
            kind: "email",
            recipient: "user@example.test".to_owned(),
            body: "123456".to_owned(),
        });
        let captured = sink.snapshot();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].body, "123456");
    }

    /// The buffer is bounded and drops the OLDEST, because a test asserts against what it
    /// just triggered.
    #[test]
    fn the_buffer_is_bounded_and_keeps_the_newest() {
        let sink = sink();
        for n in 0..(CAPACITY + 5) {
            sink.push(Captured {
                kind: "email",
                recipient: format!("user{n}@example.test"),
                body: n.to_string(),
            });
        }
        let captured = sink.snapshot();
        assert_eq!(captured.len(), CAPACITY);
        assert_eq!(
            captured.last().expect("newest").body,
            (CAPACITY + 4).to_string()
        );
        assert_eq!(captured.first().expect("oldest").body, "5");
    }

    /// A recipient or body containing JSON metacharacters must not break the document. A
    /// consumer parsing this is a CI script, and a sink that emitted invalid JSON on one
    /// unusual address would fail it for a reason having nothing to do with the login.
    #[test]
    fn json_metacharacters_are_escaped() {
        let sink = sink();
        sink.push(Captured {
            kind: "email",
            recipient: "od\"d\\name@example.test".to_owned(),
            body: "line\nbreak".to_owned(),
        });
        let json = sink.to_json();
        assert!(json.contains(r#"od\"d\\name@example.test"#), "{json}");
        assert!(json.contains(r"line\nbreak"), "{json}");
        assert!(
            !json.contains('\n'),
            "a raw newline is not legal in a JSON string: {json}"
        );
    }

    /// The generic notification carries no code, so it is not recorded: filling a bounded
    /// buffer with messages nobody reads would evict the ones somebody does.
    #[test]
    fn the_codeless_notification_is_not_recorded() {
        let sink = sink();
        // A GENERATED scope, not a hand-written identifier. A fabricated one fails to
        // parse, and the test would then die before reaching the behaviour it names --
        // passing or failing for a reason that has nothing to do with the sink.
        let (env, _clock) = ironauth_env::Env::deterministic(std::time::UNIX_EPOCH, 1);
        let scope = Scope::new(
            ironauth_store::TenantId::generate(&env),
            ironauth_store::EnvironmentId::generate(&env),
        );
        VerificationSender::send(
            &sink,
            scope,
            VerificationPurpose::Registration,
            "user@example.test",
        );
        assert!(sink.snapshot().is_empty());
    }

    /// A scope to stamp the messages with. Its value is never asserted: the sink records
    /// what a test needs to READ a code back, and the scope is not part of that.
    fn scope() -> Scope {
        let env = ironauth_env::Env::from_parts(
            std::sync::Arc::new(ironauth_env::SystemClock),
            std::sync::Arc::new(ironauth_env::FixedEntropy::new(1)),
        );
        Scope::new(
            ironauth_store::TenantId::generate(&env),
            ironauth_store::EnvironmentId::generate(&env),
        )
    }

    /// Every message the emulator can capture, retrieved through the ENDPOINT'S OWN payload
    /// (issue #121, criterion 5: "Captured email and SMS messages are retrievable via the
    /// local sink endpoint").
    ///
    /// The tests around this one push straight into the buffer, which exercises the buffer
    /// and skips the four trait methods that are the only way a real send ever reaches it.
    /// So nothing said an SMS was captured at all, and nothing said a captured message was
    /// tagged with the kind a caller filters on: `dev-otp-login.sh` selects
    /// `m["kind"] == "email"`, and an SMS landing under the wrong kind, or not landing, would
    /// have looked identical to a provider that was simply not exercised.
    #[test]
    fn an_email_a_magic_link_and_an_sms_are_all_retrievable_from_the_endpoint() {
        let sink = sink();
        let scope = scope();

        assert_eq!(
            sink.snapshot().len(),
            0,
            "nothing is captured before a send, so a later non-empty read is caused by one"
        );

        VerificationSender::deliver_email_otp(
            &sink,
            &EmailOtpMessage {
                scope,
                purpose: EmailFactorPurpose::Login,
                recipient: "user@example.test",
                code: "123456",
                ttl_secs: 300,
            },
        );
        VerificationSender::deliver_magic_link(
            &sink,
            &MagicLinkMessage {
                scope,
                purpose: EmailFactorPurpose::Login,
                recipient: "user@example.test",
                link: "http://127.0.0.1:1/magic?token=abc",
                short_code: "WXYZ",
                ttl_secs: 300,
            },
        );
        SmsSender::send(
            &sink,
            &SmsOtpMessage {
                scope,
                purpose: EmailFactorPurpose::Mfa,
                recipient: "+15551234567",
                route_key: "1",
                code: "654321",
                ttl_secs: 300,
            },
        );

        // Parsed out of the endpoint's response, not the in-memory buffer: the criterion is
        // about what a caller can RETRIEVE, and a `snapshot` assertion would hold even if the
        // response serialization dropped a field or a whole message.
        let response = sink_response(&sink);
        let body = response.split_once("\r\n\r\n").expect("a body").1;
        let messages = serde_json::from_str::<serde_json::Value>(body).expect("valid JSON")
            ["messages"]
            .as_array()
            .expect("a messages array")
            .clone();

        assert_eq!(messages.len(), 3, "all three sends are retrievable");

        let find = |kind: &str, recipient: &str| {
            messages
                .iter()
                .find(|message| {
                    message["kind"] == kind && message["recipient"] == recipient
                })
                .unwrap_or_else(|| panic!("no {kind} message for {recipient} in {body}"))
                .clone()
        };

        // The email OTP: the body IS the code, because that is what a CI job reads back.
        assert_eq!(find("email", "user@example.test")["body"], "123456");
        // The SMS is tagged `sms`, so an email-filtering caller does not pick it up and an
        // SMS-filtering caller does.
        assert_eq!(find("sms", "+15551234567")["body"], "654321");
        // The magic link carries the LINK, not the short code: the link is the thing a test
        // cannot reconstruct, and it is filed under `email` because that is how it was sent.
        assert_eq!(
            messages
                .iter()
                .filter(|message| message["kind"] == "email")
                .count(),
            2,
            "the magic link is an email, so it is retrievable as one"
        );
        assert!(
            messages
                .iter()
                .any(|message| message["body"] == "http://127.0.0.1:1/magic?token=abc"),
            "the magic link's URL is retrievable, not just its short code: {body}"
        );
    }

    /// The response is `no-store`. It carries live one-time codes, so a cache anywhere on
    /// the path holding them is exactly the leak the loopback-only design is avoiding.
    #[test]
    fn the_response_refuses_caching() {
        let response = sink_response(&sink());
        assert!(response.contains("Cache-Control: no-store"), "{response}");
        assert!(response.contains("application/json"), "{response}");
    }
}
