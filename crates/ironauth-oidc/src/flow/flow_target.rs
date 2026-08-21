//! Synchronous HTTP flow target dispatch (issue #112).
//!
//! An operator registers an HTTP endpoint that IronAuth calls out to at a point in a flow.
//! A SYNC target is on the critical path: the flow waits for it, and its answer can reject
//! the flow with per-field errors. This module is the dispatcher for that case.
//!
//! Three properties are the feature, and each is a test rather than a comment:
//!
//! * A pre-persist target runs BEFORE the write is attempted, so a rejection leaves no row.
//!   It does NOT run inside the write's transaction: an outbound call there would hold a
//!   pooled connection and the write's row locks for the target's whole timeout.
//! * A target that does not answer takes its configured [`FailurePolicy`]. A target that
//!   ANSWERS with a rejection does not: `FailOpen` means "an unanswered call counts as
//!   approval", never "ignore a rejection", and collapsing the two would make a fail-open
//!   fraud check unable to reject anything.
//! * A rejection names its field with an RFC 6901 pointer, which is resolved onto the form's
//!   nodes. If ANY pointer fails to resolve, the whole verdict is discarded and the
//!   unavailable path runs, because attaching the resolvable subset would let one typo
//!   silently defang a fail-closed rejection.
//!
//! What this module does NOT do: it does not mount a management route, so an operator cannot
//! yet register a target over HTTP (`flow_targets` grants INSERT to `ironauth_control` only).
//! Registration is `ActingFlowTargetRepo::set`, which the management PR mounts. Nor does it
//! deliver ASYNC targets; that path enqueues through the webhook machinery and has no
//! consumer yet.

use std::time::{Duration, SystemTime};

use http::header::CONTENT_TYPE;
use http::{HeaderName, HeaderValue, Method};
use ironauth_store::flow_target::{FailurePolicy, FlowTargetRecord, TargetClass, Timing};
use ironauth_store::{Scope, SignupFormConfig, SignupStep, TraitSchema};
use serde::Deserialize;

use super::message::{self, Message, MessageContext};
use super::signup_fields::{self, TargetField};
use crate::state::OidcState;

/// The ceiling on a sync target's configured timeout.
///
/// A sync target sits on a live signup, so its bound is a promise to the person waiting.
/// The flow-target `Fetcher` is constructed with exactly this as its `total_timeout`, and
/// [`ironauth_fetch::FetchRequest::timeout`] only ever SHORTENS that, so a target registered
/// above this ceiling would be truncated to it silently and the operator's stated bound would
/// be quietly false. Rather than cap without saying so, a record above the ceiling is treated
/// as misconfigured and takes the unavailable path.
pub const MAX_SYNC_TIMEOUT_MS: i32 = 30_000;

/// The whole budget one dispatch may spend, across EVERY target of that timing.
///
/// The per-target ceiling bounds one call; nothing bounded the sum. Dispatch is sequential
/// and the registry read has no `LIMIT`, so N registered targets put `N * 30s` on a live
/// signup and the person waits for all of it. This is the aggregate, and a target reached
/// with less than its own bound remaining is given only what is left rather than the full
/// ceiling.
///
/// Once it is gone the remaining targets take the unavailable path and their own failure
/// policy, which is the same answer a target that did not respond in time would get, because
/// from the flow's point of view that is exactly what happened.
const MAX_DISPATCH_BUDGET_MS: i64 = 45_000;

/// How long a signed response stays acceptable, in seconds. The same tolerance the webhook
/// delivery path uses, so an integrator's receiver code carries over unchanged.
const RESPONSE_TOLERANCE_SECS: i64 = 300;

/// A rejection the dispatcher resolved onto a real form field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedFieldError {
    /// Which field the target named.
    pub field: TargetField,
    /// The target's own explanation, capped, or [`None`] if it sent none.
    pub reason: Option<String>,
}

/// What the flow should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Decision {
    /// No sync target of this timing objected. Continue.
    Allow,
    /// A target rejected the flow, naming these fields.
    Interrupt(Vec<ResolvedFieldError>),
    /// A fail-closed target could not be consulted, or the target registry could not be read.
    /// The flow stops without a field-level explanation, because there is nothing truthful to
    /// say about which field was wrong.
    Refuse,
}

/// The wire response a sync target returns.
#[derive(Debug, Deserialize)]
struct TargetResponse {
    verdict: String,
    #[serde(default)]
    errors: Vec<TargetResponseError>,
}

/// One field-level error inside an `interrupt` verdict.
#[derive(Debug, Deserialize)]
struct TargetResponseError {
    pointer: String,
    #[serde(default)]
    message: Option<String>,
}

/// A target's free text is bounded before it becomes a message parameter. A registered target
/// is operator-configured but third-party-operated, and an unbounded string would ride into
/// every rendered page and every API response.
const MAX_REASON_CHARS: usize = 200;

fn cap_reason(message: Option<String>) -> Option<String> {
    let text = message?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_REASON_CHARS).collect())
}

/// Dispatch every enabled SYNC target of `timing` for the request class, in name order.
///
/// Returns [`Decision::Allow`] when nothing objected, INCLUDING the common case where no
/// target is registered at all, which performs no outbound call.
pub(super) async fn dispatch_sync(
    state: &OidcState,
    scope: Scope,
    timing: Timing,
    data: &serde_json::Value,
    signup: Option<&(SignupFormConfig, TraitSchema, i32)>,
) -> Decision {
    // A registry read that failed refuses rather than continues: a target that cannot be
    // listed cannot be consulted, and continuing would silently skip every fail-closed
    // integration the operator configured.
    let Ok(targets) = state
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(TargetClass::Request)
        .await
    else {
        return Decision::Refuse;
    };

    let due: Vec<&FlowTargetRecord> = targets
        .iter()
        .filter(|target| target.runs_before_write() == matches!(timing, Timing::PrePersist))
        .filter(|target| {
            matches!(
                target.invocation,
                ironauth_store::flow_target::Invocation::Sync
            )
        })
        .collect();

    if due.is_empty() {
        return Decision::Allow;
    }

    // MONOTONIC, not wall clock. `Env::now_utc`'s own contract says it "may jump backwards
    // (NTP steps); never use it to measure elapsed time" -- and the consequences here are
    // both real: a backwards step made `remaining` EXCEED the budget, restoring the
    // unbounded N*30s this exists to bound, and a forwards step past 45s exhausted it and
    // refused a signup no target was slow for, because the policy defaults to fail_closed.
    let started = state.env().clock().monotonic();
    for target in due {
        // What remains of the SHARED budget, not the full per-target ceiling.
        let remaining = budget_remaining_ms(
            state
                .env()
                .clock()
                .monotonic()
                .saturating_duration_since(started),
        );
        if remaining <= 0 {
            match apply_policy(Outcome::Unavailable, target.failure_policy) {
                Step::Continue => continue,
                Step::Stop(decision) => return decision,
            }
        }
        // The two store reads live HERE so that `consult_target` below, which owns every
        // HTTP and policy decision, needs no database and is reachable from a unit test.
        // A target configured to be signed whose secret will not open is never called
        // unsigned; the webhook delivery path makes the same refusal. It is the unavailable
        // path rather than a skip, so a fail-closed target still refuses.
        let Ok(secret) = state
            .store()
            .scoped(scope)
            .flow_targets()
            .open_signing_secret(target)
            .await
        else {
            match apply_policy(Outcome::Unavailable, target.failure_policy) {
                Step::Continue => continue,
                Step::Stop(decision) => return decision,
            }
        };
        // A target is registered and there is nothing to call it with. NOT a skip: treating
        // it as one would let a boot that forgot to install a fetcher silently disarm every
        // fail-closed target.
        let Some(fetcher) = state.flow_target_fetcher() else {
            match apply_policy(Outcome::Unavailable, target.failure_policy) {
                Step::Continue => continue,
                Step::Stop(decision) => return decision,
            }
        };
        let now = unix_secs(state.env().clock().now_utc());
        // Minted PER CONSULTATION. See `flow_target::delivery_id`: `webhook-id` is the
        // receiver's deduplication handle, so a constant one silently turns every call after
        // the first into a replay of the first.
        let delivery = ironauth_store::flow_target::delivery_id(
            &target.id,
            &ironauth_store::CorrelationId::generate(state.env()).to_string(),
        );
        let outcome = consult_target(
            fetcher,
            target,
            secret.as_deref(),
            timing,
            scope,
            data,
            signup,
            now,
            &delivery,
            remaining,
        )
        .await;
        match apply_policy(outcome, target.failure_policy) {
            Step::Continue => {}
            Step::Stop(decision) => return decision,
        }
    }
    Decision::Allow
}

/// The result of consulting ONE target.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Allow,
    Interrupt(Vec<ResolvedFieldError>),
    Unavailable,
}

/// What the dispatch loop does with one target's outcome.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Move on to the next target.
    Continue,
    /// Stop, with this decision.
    Stop(Decision),
}

/// Map one target's outcome and its policy onto the loop's next move.
///
/// The row that matters is `Interrupt`: it does NOT consult the policy. `FailOpen` means "an
/// unanswered call counts as approval", never "ignore a rejection", and collapsing the two
/// would make a fail-open fraud check unable to reject anything, which is the opposite of
/// what an operator configuring one is asking for. Every other non-allow outcome, however it
/// arose, is `Unavailable` and does consult the policy.
fn apply_policy(outcome: Outcome, policy: FailurePolicy) -> Step {
    match outcome {
        Outcome::Allow => Step::Continue,
        // A rejection ALWAYS stops, whatever the policy says. An empty list is still a
        // rejection: it means the target refused and its field mapping could not be
        // resolved, so the flow refuses uniformly rather than inventing a field or, worse,
        // treating the refusal as an unanswered call and forgiving it.
        Outcome::Interrupt(errors) if errors.is_empty() => Step::Stop(Decision::Refuse),
        Outcome::Interrupt(errors) => Step::Stop(Decision::Interrupt(errors)),
        Outcome::Unavailable => match policy {
            FailurePolicy::FailOpen => Step::Continue,
            FailurePolicy::FailClosed => Step::Stop(Decision::Refuse),
        },
    }
}

/// Consult ONE target over HTTP and classify its answer.
///
/// Takes the fetcher and the already-opened secret rather than reaching for them, so every
/// decision below (the timeout bound, the signature, the status check, the parse, the pointer
/// resolution) is exercisable without a database.
#[allow(clippy::too_many_arguments)]
async fn consult_target(
    fetcher: &ironauth_fetch::Fetcher,
    target: &FlowTargetRecord,
    secret: Option<&[u8]>,
    timing: Timing,
    scope: Scope,
    data: &serde_json::Value,
    signup: Option<&(SignupFormConfig, TraitSchema, i32)>,
    now: i64,
    delivery_id: &str,
    budget_remaining_ms: i64,
) -> Outcome {
    // A sync target without a bound cannot satisfy criterion 6 at all, and one above the
    // ceiling would be silently truncated. Both are misconfiguration, not a network event,
    // and both are refused BEFORE any call is made.
    let Some(timeout_ms) = target.timeout_ms else {
        return Outcome::Unavailable;
    };
    if timeout_ms <= 0 || timeout_ms > MAX_SYNC_TIMEOUT_MS {
        return Outcome::Unavailable;
    }
    // Never more than what is left of the shared budget, so the aggregate holds however many
    // targets are registered.
    let Ok(timeout_ms) = u64::try_from(i64::from(timeout_ms).min(budget_remaining_ms)) else {
        return Outcome::Unavailable;
    };

    // Built PER TARGET, not once for the batch: `target_id` and `config` differ per target,
    // and a shared envelope would ship one target's configuration to another.
    let envelope = serde_json::json!({
        "target_id": target.id.to_string(),
        "class": "request",
        "timing": match timing {
            Timing::PrePersist => "pre_persist",
            Timing::PostPersist => "post_persist",
        },
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "data": data,
        "config": target.config,
    });
    let Ok(body) = serde_json::to_vec(&envelope) else {
        return Outcome::Unavailable;
    };
    let timestamp = now;

    let mut request = ironauth_fetch::FetchRequest::new(
        ironauth_fetch::FetchPurpose::FlowTarget,
        Method::POST,
        target.endpoint.clone(),
    )
    .timeout(Duration::from_millis(timeout_ms))
    .body(body.clone());

    let Ok(content_type) = HeaderValue::from_str("application/json") else {
        return Outcome::Unavailable;
    };
    request = request.header(CONTENT_TYPE, content_type);

    if let Some(bytes) = secret {
        let webhook_secret = ironauth_jose::webhooks::WebhookSecret::from_bytes(bytes.to_vec());
        // Signed under the PER-CALL delivery id, not the target id. `webhook-id` is the
        // receiver's deduplication handle (the webhook delivery path says so in as many
        // words, and the config docs repeat it), so a constant one makes every consultation
        // after the first look like a replay of the first: a receiver written to this
        // repository's own guidance would drop it, or echo its cached first answer, and a
        // fraud check would be bypassed with nobody attacking it.
        let signature = ironauth_store::flow_target::sign_payload(
            &webhook_secret,
            delivery_id,
            timestamp,
            &body,
        );
        let Some(headers) = signed_headers(delivery_id, timestamp, &signature) else {
            return Outcome::Unavailable;
        };
        for (name, value) in headers {
            request = request.header(name, value);
        }
    }

    // Every transport failure lands here identically: a timeout, a blocked destination, a
    // refused scheme, an oversize body, an un-followed redirect. A match arm naming only
    // `Timeout` would let the others through as something other than unavailable.
    let Ok(response) = fetcher.fetch(request).await else {
        return Outcome::Unavailable;
    };

    classify_response(&response, secret, delivery_id, now, signup)
}

/// What ONE target's answer means.
///
/// Split from the call itself because it is a different question, and because every branch
/// below is a decision an operator's fail-closed target depends on: a non-2xx honoured as
/// approval, an unverifiable signature accepted, or an unknown verdict string read as
/// `allow` would each silently disarm the check.
fn classify_response(
    response: &ironauth_fetch::FetchResponse,
    secret: Option<&[u8]>,
    delivery_id: &str,
    now: i64,
    signup: Option<&(SignupFormConfig, TraitSchema, i32)>,
) -> Outcome {
    // `fetch` returns `Ok` for any COMPLETED exchange, so a 500 carrying a well-formed
    // `allow` body would otherwise be honoured as approval.
    if !response.status().is_success() {
        return Outcome::Unavailable;
    }

    if let Some(bytes) = secret {
        // Verified under the SAME per-call id the request was signed with, so a captured
        // response cannot be replayed against a later consultation inside the tolerance.
        if !response_signature_verifies(delivery_id, bytes, response, now) {
            return Outcome::Unavailable;
        }
    }

    let Ok(parsed) = serde_json::from_slice::<TargetResponse>(response.body()) else {
        return Outcome::Unavailable;
    };

    match parsed.verdict.as_str() {
        "allow" => Outcome::Allow,
        "interrupt" => {
            // Built through the SHIPPED type rather than re-checking here: `TargetVerdict`
            // owns the rule that a verdict carrying no errors is not an interruption, and a
            // second copy of that rule in this module is a second place for it to drift.
            let errors = parsed
                .errors
                .into_iter()
                .map(|error| ironauth_store::flow_target::FieldError {
                    pointer: error.pointer,
                    message: error.message.unwrap_or_default(),
                })
                .collect();
            let Ok(verdict) = ironauth_store::flow_target::TargetVerdict::interrupt(errors) else {
                // An interrupt with nothing to say cannot be rendered on any field.
                return Outcome::Unavailable;
            };
            let ironauth_store::flow_target::TargetVerdict::Interrupt(parsed_errors) = verdict
            else {
                return Outcome::Unavailable;
            };
            Outcome::Interrupt(resolve_errors(parsed_errors, signup))
        }
        // An unknown verdict string is a contract violation, not an approval.
        _ => Outcome::Unavailable,
    }
}

/// Build the three Standard Webhooks headers, or [`None`] if any value is not a legal header.
fn signed_headers(
    id: &str,
    timestamp: i64,
    signature: &str,
) -> Option<Vec<(HeaderName, HeaderValue)>> {
    Some(vec![
        (
            HeaderName::from_static("webhook-id"),
            HeaderValue::from_str(id).ok()?,
        ),
        (
            HeaderName::from_static("webhook-timestamp"),
            HeaderValue::from_str(&timestamp.to_string()).ok()?,
        ),
        (
            HeaderName::from_static("webhook-signature"),
            HeaderValue::from_str(signature).ok()?,
        ),
    ])
}

/// Verify a target's RESPONSE signature under the same secret its request was signed with.
///
/// Without this, an on-path attacker can approve or reject a signup by rewriting the body,
/// which is why issue #112's verification section names it as a required adversarial case.
fn response_signature_verifies(
    id: &str,
    secret: &[u8],
    response: &ironauth_fetch::FetchResponse,
    now: i64,
) -> bool {
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let (Some(timestamp), Some(signature)) =
        (header("webhook-timestamp"), header("webhook-signature"))
    else {
        return false;
    };
    let secrets = [ironauth_jose::webhooks::WebhookSecret::from_bytes(
        secret.to_vec(),
    )];
    ironauth_jose::webhooks::verify_delivery(
        &secrets,
        id,
        timestamp,
        response.body(),
        signature,
        RESPONSE_TOLERANCE_SECS,
        now,
    )
    .is_ok()
}

/// What is left of the shared dispatch budget after `elapsed`.
///
/// A pure function so the arithmetic is testable without a database or a clock. It was
/// inline, and both the cap and the exhaustion guard survived mutation because nothing could
/// reach them.
fn budget_remaining_ms(elapsed: Duration) -> i64 {
    let spent = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
    MAX_DISPATCH_BUDGET_MS.saturating_sub(spent)
}

/// Seconds since the Unix epoch for a wall-clock instant (saturating), the same derivation
/// `backchannel.rs` and the webhook delivery path use, so a receiver sees one timestamp
/// discipline across every signed IronAuth call.
fn unix_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Split resolved rejections into the shape the registration renderer already takes.
///
/// The identifier and password errors ride as message ids on the built-in nodes, and every
/// configured signup field rides as a [`signup_fields::FieldFailure`], which is the mapping
/// the signup validation path already owns. Reusing it is what makes a target's rejection
/// render on the SAME node as IronAuth's own validation failure, on both transports.
pub(super) fn split_for_render(
    errors: &[ResolvedFieldError],
) -> (
    Option<Message>,
    Option<Message>,
    Vec<signup_fields::FieldFailure>,
) {
    let mut identifier = None;
    let mut password = None;
    let mut failures = Vec::new();
    for error in errors {
        // Which id depends on whether the target explained itself, because interpolation
        // leaves an unreferenced placeholder verbatim: the `{reason}` template with no
        // reason in context would render the literal string `{reason}` to a person.
        let id = if error.reason.is_some() {
            message::FLOW_TARGET_REJECTED_WITH_REASON
        } else {
            message::FLOW_TARGET_REJECTED
        };
        match &error.field {
            // The built-ins take a whole MESSAGE, carrying the reason in its context. An
            // earlier revision handed back an id alone, which forced `Message::of` and an
            // EMPTY context at the node: the with-reason template then rendered its
            // placeholder literally and the target's text was dropped on the way. The
            // signup-field arm below never had that bug, which is exactly why it went
            // unnoticed: one of the three arms was right.
            TargetField::Identifier => identifier = Some(built_in_message(id, error)),
            TargetField::Password => password = Some(built_in_message(id, error)),
            TargetField::Trait(pointer) => failures.push(signup_fields::FieldFailure {
                trait_pointer: pointer.clone(),
                message_id: id,
                reason: error.reason.clone(),
            }),
        }
    }
    (identifier, password, failures)
}

/// Map a target's field errors onto form fields, or return an EMPTY list if any one of them
/// names a field this step does not render.
///
/// Empty is not "no rejection". It is "rejected, and nothing truthful to say about which
/// field", which [`apply_policy`] turns into a uniform refusal under either policy. Returning
/// `Unavailable` instead (as an earlier revision did) routed a deliberate refusal through the
/// FAILURE POLICY, and under `FailOpen` that means allow: the target said no and was ignored.
/// That is the exact collapse this module's header forbids, and it bit hardest on the legacy
/// `/register` route, which passes no signup form, so every trait pointer was unresolvable.
///
/// All-or-nothing on the mapping, deliberately: attaching only the resolvable subset would let
/// one typo in one pointer silently drop the field that actually mattered.
fn resolve_errors(
    errors: Vec<ironauth_store::flow_target::FieldError>,
    signup: Option<&(SignupFormConfig, TraitSchema, i32)>,
) -> Vec<ResolvedFieldError> {
    let mut resolved = Vec::with_capacity(errors.len());
    for error in errors {
        let Some(field) =
            signup_fields::resolve_target_pointer(&error.pointer, signup, SignupStep::Signup)
        else {
            return Vec::new();
        };
        resolved.push(ResolvedFieldError {
            field,
            reason: cap_reason(Some(error.message)),
        });
    }
    resolved
}

/// Build a built-in field's rejection message, carrying the pointer and, when the target
/// sent one, its own explanation.
///
/// The `field` key is the WIRE pointer rather than a node name, so a client keying off it
/// reads the same namespace it would have sent, and the same key a signup-field rejection
/// carries.
fn built_in_message(id: message::MessageId, error: &ResolvedFieldError) -> Message {
    let pointer = match error.field {
        TargetField::Identifier => "/identifier",
        TargetField::Password => "/password",
        TargetField::Trait(_) => "",
    };
    let mut context = MessageContext::one(signup_fields::FIELD_CONTEXT_KEY, pointer);
    if let Some(reason) = &error.reason {
        context
            .0
            .insert(signup_fields::REASON_CONTEXT_KEY.to_owned(), reason.clone());
    }
    Message::with_context(id, context)
}

/// The flow level message a [`Decision::Refuse`] renders.
pub(super) fn refusal_message() -> Message {
    Message::with_context(message::FLOW_TARGET_UNAVAILABLE, MessageContext::empty())
}

#[cfg(test)]
mod tests {
    use super::{
        Decision, Duration, MAX_DISPATCH_BUDGET_MS, MAX_REASON_CHARS, Outcome, ResolvedFieldError,
        Step, apply_policy, budget_remaining_ms, cap_reason, resolve_errors, split_for_render,
    };
    use crate::flow::message;
    use crate::flow::signup_fields::TargetField;
    use ironauth_store::flow_target::FailurePolicy;

    fn interrupt() -> Outcome {
        Outcome::Interrupt(vec![ResolvedFieldError {
            field: TargetField::Identifier,
            reason: None,
        }])
    }

    /// The policy table, all six rows.
    ///
    /// The two that matter are the `Interrupt` rows. `FailOpen` means "an unanswered call
    /// counts as approval", NOT "ignore a rejection": a fail-open target that collapsed the
    /// two would be unable to reject anything, which is the exact opposite of what an
    /// operator who configured a fraud check is asking for.
    #[test]
    fn fail_open_forgives_silence_but_never_forgives_a_rejection() {
        assert_eq!(
            apply_policy(Outcome::Allow, FailurePolicy::FailOpen),
            Step::Continue
        );
        assert_eq!(
            apply_policy(Outcome::Allow, FailurePolicy::FailClosed),
            Step::Continue,
            "an approval is an approval under either policy"
        );

        assert_eq!(
            apply_policy(Outcome::Unavailable, FailurePolicy::FailOpen),
            Step::Continue,
            "fail open forgives a target that did not answer"
        );
        assert_eq!(
            apply_policy(Outcome::Unavailable, FailurePolicy::FailClosed),
            Step::Stop(Decision::Refuse),
            "fail closed refuses when it could not be consulted"
        );

        let Step::Stop(Decision::Interrupt(open)) =
            apply_policy(interrupt(), FailurePolicy::FailOpen)
        else {
            panic!(
                "a FAIL OPEN target that rejects must still reject: fail open describes \
                   what an unanswered call means, not what a rejection means"
            );
        };
        assert_eq!(open.len(), 1);
        let Step::Stop(Decision::Interrupt(closed)) =
            apply_policy(interrupt(), FailurePolicy::FailClosed)
        else {
            panic!("a fail closed target that rejects rejects for the same reason");
        };
        assert_eq!(closed.len(), 1);
    }

    /// Which message id a rejection carries depends on whether the target explained itself.
    ///
    /// Not cosmetic: `interpolate` leaves an unreferenced `{placeholder}` VERBATIM, so a
    /// single id whose template is `{reason}` would render the literal string `{reason}` to a
    /// person whenever the target sent no message.
    #[test]
    fn a_rejection_without_a_reason_uses_the_template_that_has_no_placeholder() {
        let (identifier, password, failures) = split_for_render(&[
            ResolvedFieldError {
                field: TargetField::Identifier,
                reason: None,
            },
            ResolvedFieldError {
                field: TargetField::Password,
                reason: Some("too weak for this tenant".to_owned()),
            },
            ResolvedFieldError {
                field: TargetField::Trait("/email".to_owned()),
                reason: Some("domain is blocklisted".to_owned()),
            },
            ResolvedFieldError {
                field: TargetField::Trait("/age".to_owned()),
                reason: None,
            },
        ]);

        let identifier = identifier.expect("the identifier rejection is carried through");
        assert_eq!(
            identifier.id,
            message::FLOW_TARGET_REJECTED,
            "no reason means the template WITHOUT the placeholder"
        );
        assert_eq!(
            identifier.context.0.get("reason"),
            None,
            "and nothing to interpolate"
        );

        let password = password.expect("the password rejection is carried through");
        assert_eq!(
            password.id,
            message::FLOW_TARGET_REJECTED_WITH_REASON,
            "a reason means the template that interpolates it"
        );
        // THE regression this test exists for. An earlier revision returned an id alone for
        // the two built-in fields, which forced an EMPTY context at the node, so the
        // `{reason}` template rendered its placeholder LITERALLY to the person and the
        // target's text was discarded. Asserting the id alone passed while that was true.
        assert_eq!(
            password.context.0.get("reason").map(String::as_str),
            Some("too weak for this tenant"),
            "the target's own text must reach the context, or the with-reason template \
             renders the literal placeholder and the explanation is lost"
        );
        assert_eq!(
            password.context.0.get("field").map(String::as_str),
            Some("/password"),
            "and the wire pointer rides alongside it, as it does for a signup field"
        );

        let email = failures
            .iter()
            .find(|failure| failure.trait_pointer == "/email")
            .expect("the email failure is carried through");
        assert_eq!(email.message_id, message::FLOW_TARGET_REJECTED_WITH_REASON);
        assert_eq!(email.reason.as_deref(), Some("domain is blocklisted"));

        let age = failures
            .iter()
            .find(|failure| failure.trait_pointer == "/age")
            .expect("the age failure is carried through");
        assert_eq!(
            age.message_id,
            message::FLOW_TARGET_REJECTED,
            "each failure picks its id from ITS OWN reason, not from the first one"
        );
        assert_eq!(age.reason, None);
    }

    /// A rejection we cannot MAP is still a rejection, under either policy.
    ///
    /// The regression this pins: an unresolvable pointer used to become `Unavailable`, which
    /// routed a deliberate refusal through the failure policy, and under `FailOpen` that is
    /// "allow". A target that answered `interrupt` was silently ignored. It bit hardest on
    /// the legacy `/register` route, which passes no signup form at all, so EVERY trait
    /// pointer was unresolvable there.
    #[test]
    fn a_rejection_that_cannot_be_mapped_still_refuses_under_fail_open() {
        assert_eq!(
            apply_policy(Outcome::Interrupt(Vec::new()), FailurePolicy::FailOpen),
            Step::Stop(Decision::Refuse),
            "fail open forgives an unanswered call, never a refusal it could not render"
        );
        assert_eq!(
            apply_policy(Outcome::Interrupt(Vec::new()), FailurePolicy::FailClosed),
            Step::Stop(Decision::Refuse),
        );
        // And it is distinguishable from silence, which fail open DOES forgive.
        assert_eq!(
            apply_policy(Outcome::Unavailable, FailurePolicy::FailOpen),
            Step::Continue,
        );
    }

    /// An unmappable pointer yields an EMPTY error list, which is a rejection, not silence.
    ///
    /// This is the production half of the same defect the policy test above pins. Together
    /// they cover it end to end: this proves an unresolvable pointer PRODUCES the empty
    /// list, and that one proves the empty list REFUSES under fail-open. Testing only the
    /// second left a mutant alive that turned the first back into `Unavailable`.
    #[test]
    fn a_pointer_this_step_cannot_render_maps_to_no_fields_rather_than_to_silence() {
        let error = |pointer: &str| ironauth_store::flow_target::FieldError {
            pointer: pointer.to_owned(),
            message: "blocked".to_owned(),
        };

        // The legacy /register route passes no form at all, so EVERY trait pointer is
        // unresolvable there. It must still be a rejection.
        assert!(
            resolve_errors(vec![error("/traits/email")], None).is_empty(),
            "with no form, a trait pointer cannot be mapped, and the rejection must survive \
             as an unmappable one rather than becoming an unanswered call"
        );

        // A built-in resolves even with no form, so that case maps normally.
        assert_eq!(
            resolve_errors(vec![error("/identifier")], None).len(),
            1,
            "the built-in fields need no signup form to resolve"
        );

        // One bad pointer discards the WHOLE mapping, not just its own entry.
        let resolved = resolve_errors(vec![error("/identifier"), error("/traits/nope")], None);
        assert!(
            resolved.is_empty(),
            "attaching only the resolvable subset would let one typo silently drop the field \
             that actually mattered"
        );
    }

    /// The shared budget shrinks with elapsed time and never goes below zero-ish nonsense.
    ///
    /// Pure arithmetic, extracted precisely because it was unreachable inline: both the cap
    /// and the exhaustion guard survived mutation while nothing could call them.
    #[test]
    fn the_dispatch_budget_shrinks_and_then_runs_out() {
        assert_eq!(
            budget_remaining_ms(Duration::ZERO),
            MAX_DISPATCH_BUDGET_MS,
            "nothing spent yet"
        );
        assert_eq!(
            budget_remaining_ms(Duration::from_secs(1)),
            MAX_DISPATCH_BUDGET_MS - 1_000
        );
        assert_eq!(
            budget_remaining_ms(Duration::from_millis(
                u64::try_from(MAX_DISPATCH_BUDGET_MS).expect("the budget is positive")
            )),
            0,
            "exactly spent is exhausted, and the caller's guard is `<= 0`"
        );
        assert!(
            budget_remaining_ms(Duration::from_secs(3_600)) < 0,
            "overspent stays negative rather than wrapping into a fresh budget"
        );
        assert!(
            budget_remaining_ms(Duration::MAX) < 0,
            "a saturating conversion must not hand back a full budget"
        );
    }

    /// A target's free text is bounded, trimmed, and an empty explanation is no explanation.
    #[test]
    fn a_target_reason_is_capped_and_an_empty_one_is_none() {
        assert_eq!(cap_reason(None), None);
        assert_eq!(
            cap_reason(Some("   ".to_owned())),
            None,
            "whitespace is not an explanation"
        );
        assert_eq!(
            cap_reason(Some("  spaced  ".to_owned())),
            Some("spaced".to_owned())
        );

        let long = "x".repeat(MAX_REASON_CHARS + 50);
        let capped = cap_reason(Some(long)).expect("a long reason is kept, not dropped");
        assert_eq!(
            capped.chars().count(),
            MAX_REASON_CHARS,
            "a registered target is operator configured but third party operated; an \
             unbounded string would ride into every rendered page and API response"
        );

        // Capping counts CHARACTERS, not bytes: slicing bytes would panic mid codepoint.
        let multibyte = "é".repeat(MAX_REASON_CHARS + 10);
        let capped = cap_reason(Some(multibyte)).expect("multibyte text survives");
        assert_eq!(capped.chars().count(), MAX_REASON_CHARS);
    }
}
