// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP flow target configuration (issue #112).
//!
//! The types the dispatcher branches on, kept here rather than in the repository because the
//! decisions they encode are the feature: a target's timing decides whether it runs BEFORE the
//! write or after it commits, and its failure policy decides what happens when it does not
//! answer.
//!
//! Nothing here performs IO. The registry reads rows and maps them to these; the dispatcher
//! reads these and decides. Keeping the decision types free of the database is what lets the
//! dispatch rules be tested exhaustively without one -- the same split `message_template` uses
//! for resolution.

/// The Zitadel Actions v2 taxonomy issue #112 adopts.
///
/// CLOSED on purpose, and the migration's CHECK holds the same three-plus-one set. A class the
/// dispatcher does not know would be configured, stored, and never invoked -- which an
/// operator experiences as a target that silently does nothing, the hardest kind of
/// misconfiguration to find because everything reports success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetClass {
    /// Invoked BEFORE the request is processed, and able to reject or mutate it.
    Request,
    /// Invoked AFTER processing, able to shape what is returned.
    Response,
    /// Invoked at a named point in a flow.
    Function,
    /// Fire-and-forget on an emitted event.
    Event,
}

/// Whether the flow WAITS for the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Invocation {
    /// The flow waits. The response can mutate the in-flight data or interrupt the flow, and
    /// the target's timeout therefore bounds the flow.
    Sync,
    /// The flow does not wait. Routed through the webhook delivery machinery, inheriting its
    /// retries, dead letters and replay -- which is why issue #112 does not rebuild any of
    /// them here.
    Async,
}

/// WHEN the target runs, relative to the write.
///
/// This is criterion 4, and it is the one decision that cannot be retrofitted: it is a
/// statement about transaction boundaries, so the dispatcher has to know it before it opens a
/// transaction at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Timing {
    /// Runs BEFORE the write is attempted, so no row exists yet. A rejection therefore leaves
    /// no row -- not a row that is later cleaned up, but no row ever, because the write call is
    /// never made.
    ///
    /// Before the write rather than inside its transaction: an outbound HTTP call inside one
    /// would hold a pooled Postgres connection and the write's row locks for the target's
    /// whole timeout, so a slow third party would consume the pool rather than its own budget.
    ///
    /// The header of migration 0146 still states the stronger claim, that a pre-persist target
    /// runs inside the write's transaction. It is SHIPPED and checksummed, so its text cannot
    /// be corrected without making every deployed database refuse to boot on
    /// `ChecksumMismatch`; this doc is where that correction lives.
    PrePersist,
    /// Runs AFTER commit. The target observes committed state, which is the only way it can
    /// be shown data that is guaranteed to still be there when it looks.
    PostPersist,
}

/// What happens when a SYNC target does not answer in time, or answers with an error.
///
/// Per target rather than global, because there is no safe universal answer: a fraud check
/// that fails open is not a fraud check, and a CRM sync that fails closed takes signup down
/// when the CRM does. The migration DEFAULTS it to [`Self::FailClosed`] -- a target whose
/// policy nobody stated is one nobody thought about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailurePolicy {
    /// Continue the flow as though the target had approved.
    FailOpen,
    /// Refuse the flow.
    FailClosed,
}

/// A registered target, as the dispatcher needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTargetRecord {
    /// The `ftg_` identifier.
    pub id: crate::id::FlowTargetId,
    /// The operator-facing name, unique among live targets in the environment.
    pub name: String,
    /// Which class of flow point invokes it.
    pub target_class: TargetClass,
    /// Whether the flow waits.
    pub invocation: Invocation,
    /// When it runs relative to the write.
    pub timing: Timing,
    /// Where it POSTs.
    pub endpoint: String,
    /// The bound on a sync call, in milliseconds. Always present for a sync target: the
    /// migration's CHECK refuses a sync target without one, because a target with no bound to
    /// exceed cannot satisfy criterion 6 at all.
    pub timeout_ms: Option<i32>,
    /// What to do when a sync target does not answer.
    pub failure_policy: FailurePolicy,
    /// Plain JSON. NEVER code: issue #112 names Ory's base64-embedded Jsonnet as the
    /// ergonomic failure this design exists to avoid.
    pub config: serde_json::Value,
    /// The per-target signing secret, by NAME. Resolved at call time; never held here.
    pub signing_secret_name: Option<String>,
}

impl FlowTargetRecord {
    /// Whether this target must run BEFORE the write, so a refusal leaves no row.
    ///
    /// The dispatcher calls a pre-persist target before it calls the store at all; the target
    /// does not run inside the write's database transaction, and should not. An outbound HTTP
    /// call made inside one would hold a pooled Postgres connection and whatever rows the
    /// write has locked for the target's entire timeout, so a slow third party would consume
    /// the connection pool rather than just its own budget.
    ///
    /// Running before the write satisfies criterion 4 anyway, which asks that "a rejecting
    /// pre-persist target leaves no row": a target that refuses means the write call is never
    /// made, and a call never made writes nothing. The stronger reading, an HTTP round trip
    /// inside a database transaction, buys nothing over that and costs the pool.
    ///
    /// It is a method on the record rather than something a caller derives because a caller
    /// reconstructing it from `timing` and `invocation` separately could get the async case
    /// wrong, and the async case is the one where getting it wrong means blocking a flow on
    /// something nothing waits for.
    #[must_use]
    pub fn runs_before_write(&self) -> bool {
        // An ASYNC target never does, whatever its timing says -- and the migration's CHECK
        // means an async target is always post-persist anyway, so this is belt and braces
        // rather than a second rule. Stated explicitly because the cost of the two disagreeing
        // is a flow blocked on something fire-and-forget.
        matches!(self.invocation, Invocation::Sync) && matches!(self.timing, Timing::PrePersist)
    }
}

/// The signing input for a flow target payload (issue #112 criterion 3).
///
/// Criterion 3 asks that target payloads "verify with the per-target secret using the standard
/// verification helpers". So this does not define a scheme -- it hands the delivery to
/// [`ironauth_jose::webhooks::sign_delivery`], the SAME function that signs a Standard
/// Webhooks delivery, and a receiver verifies with `verify_delivery` exactly as it does for a
/// webhook.
///
/// # Why reuse rather than a second scheme
///
/// The issue is explicit that this exists "so receivers verify with the same helpers", and the
/// reason is not tidiness: an integrator wiring both a webhook endpoint and a flow target
/// should write one verifier. A second scheme would also be a second thing to get subtly
/// wrong, and signature verification is the code where subtle wrongness is silent -- a
/// verifier that accepts too much reports nothing at all.
///
/// # Why the id is PER CALL, and why it still names the target
///
/// `sign_delivery` binds an id into what it signs, which is what stops a payload being
/// replayed against a different delivery. An earlier revision bound the TARGET id, reasoning
/// that a payload signed for one target must not verify at another sharing a secret. That
/// property is real, but the id it chose is wrong for a second reason that outweighs it:
/// `webhook-id` is the RECEIVER'S DEDUPLICATION HANDLE. The webhook delivery path says so in
/// as many words, and the configuration reference repeats it. A constant id makes every
/// consultation after the first look like a replay of the first, so a receiver written to
/// this repository's own guidance drops it or echoes its cached first answer, and a fraud
/// check is bypassed with nobody attacking anything.
///
/// So the caller passes [`delivery_id`], which is `<target id>.<per-call nonce>`: unique per
/// call, so deduplication works and a captured response cannot be replayed against a later
/// consultation inside the tolerance window, and still prefixed by the target, so the
/// cross-target property the earlier revision wanted is kept.
#[must_use]
pub fn sign_payload(
    secret: &ironauth_jose::webhooks::WebhookSecret,
    delivery_id: &str,
    timestamp_secs: i64,
    payload: &[u8],
) -> String {
    // A slice of one. `sign_delivery` takes several so a rotation overlap can sign under both
    // the old and the new secret; a flow target carries one secret name today, and passing a
    // one-element slice keeps the door open without inventing a rotation story this issue does
    // not own.
    ironauth_jose::webhooks::sign_delivery(
        std::slice::from_ref(secret),
        delivery_id,
        timestamp_secs,
        payload,
    )
}

/// The id one consultation is signed under: `<target id>.<per-call nonce>`.
///
/// Per call because `webhook-id` is the receiver's deduplication handle; prefixed by the
/// target so a payload signed for one target still cannot verify at another that happens to
/// share a secret. See [`sign_payload`].
#[must_use]
pub fn delivery_id(target_id: &crate::id::FlowTargetId, nonce: &str) -> String {
    format!("{target_id}.{nonce}")
}

/// A field-level validation error from a SYNC target (issue #112 criterion 1).
///
/// The flow interruption contract adopts Kratos's `instance_ptr` pattern, which the issue
/// names as "the proven reference for mapping a hook's validation verdict onto specific form
/// fields". That is what lets a fraud check or a CRM validation reject a signup cleanly
/// instead of with an opaque error: the headless flow API attaches the message to the field
/// the pointer names, and a hosted page or SPA renders it there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// An RFC 6901 JSON Pointer into the submitted form data, naming the offending field.
    ///
    /// A POINTER rather than a field name, because form data nests: `/traits/address/country`
    /// is a real field and "country" is ambiguous the moment a form has two of them.
    pub pointer: String,
    /// The message to render against that field.
    pub message: String,
}

/// A sync target's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetVerdict {
    /// Continue the flow.
    Allow,
    /// Interrupt the flow, attaching each error to the field its pointer names.
    ///
    /// A NON-EMPTY list is not enforced by the type, deliberately -- see
    /// [`TargetVerdict::interrupt`], which refuses to build an empty one. A verdict carrying
    /// no errors would interrupt a flow while giving the person in front of the form nothing
    /// to correct, which reads to them as the product being broken.
    Interrupt(Vec<FieldError>),
}

impl TargetVerdict {
    /// Build an interruption, refusing one with nothing to say.
    ///
    /// # Errors
    ///
    /// Returns the errors back when `errors` is empty. An interruption with no field errors
    /// is the worst possible rejection: the flow stops, the form shows nothing, and the person
    /// filling it in has no way to proceed and no idea why.
    pub fn interrupt(errors: Vec<FieldError>) -> Result<Self, Vec<FieldError>> {
        if errors.is_empty() {
            return Err(errors);
        }
        Ok(Self::Interrupt(errors))
    }

    /// Whether this verdict stops the flow.
    #[must_use]
    pub fn interrupts(&self) -> bool {
        matches!(self, Self::Interrupt(_))
    }
}

/// Build an RFC 6901 pointer from reference tokens.
///
/// Delegates the ESCAPING to `trait_schema`, which already implements RFC 6901's two
/// substitutions (`~` before `/`, order-dependent). A second escaper would be a second chance
/// to get that order wrong, and getting it wrong produces a pointer that resolves to the wrong
/// field or to nothing -- which surfaces as an error message attached to the wrong input box.
#[must_use]
pub fn field_pointer(tokens: &[&str]) -> String {
    let mut pointer = String::new();
    for token in tokens {
        crate::trait_schema::push_pointer_token(&mut pointer, token);
    }
    pointer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(invocation: Invocation, timing: Timing) -> FlowTargetRecord {
        FlowTargetRecord {
            id: crate::id::FlowTargetId::generate(
                &ironauth_env::Env::system(),
                &crate::Scope::new(
                    crate::id::TenantId::generate(&ironauth_env::Env::system()),
                    crate::id::EnvironmentId::generate(&ironauth_env::Env::system()),
                ),
            ),
            name: "t".to_owned(),
            target_class: TargetClass::Request,
            invocation,
            timing,
            endpoint: "https://target.example/hook".to_owned(),
            timeout_ms: Some(1000),
            failure_policy: FailurePolicy::FailClosed,
            config: serde_json::json!({}),
            signing_secret_name: None,
        }
    }

    /// A flow target payload verifies with the STANDARD webhook verifier (criterion 3).
    ///
    /// This is the assertion that the reuse is real rather than described. It signs with
    /// `sign_payload` and verifies with `ironauth_jose::webhooks::verify_delivery` -- the
    /// function an integrator already runs for webhook deliveries. If this ever needed its own
    /// verifier, the criterion would be unmet however well the signing worked.
    #[test]
    fn a_target_payload_verifies_with_the_standard_webhook_verifier() {
        let secret =
            ironauth_jose::webhooks::WebhookSecret::parse("whsec_c2VjcmV0LWZvci10ZXN0cw==")
                .expect("the test secret parses");
        let signed_for = target(Invocation::Sync, Timing::PrePersist);
        let payload = br#"{"email":"person@example.test"}"#;
        let now = 1_735_689_600_i64;
        // The PER-CALL id, as the dispatcher builds it.
        let this_call = delivery_id(&signed_for.id, "call-one");
        let header = sign_payload(&secret, &this_call, now, payload);

        assert!(
            ironauth_jose::webhooks::verify_delivery(
                std::slice::from_ref(&secret),
                &this_call,
                &now.to_string(),
                payload,
                &header,
                300,
                now,
            )
            .is_ok(),
            "the standard verifier must accept it, or an integrator needs a second verifier \
             for the same deployment"
        );

        // A payload signed for ONE target must not verify at another. The delivery id is
        // PREFIXED by the target, so that property survives the move to a per-call id.
        let other = target(Invocation::Sync, Timing::PrePersist);
        assert!(
            ironauth_jose::webhooks::verify_delivery(
                std::slice::from_ref(&secret),
                &delivery_id(&other.id, "call-one"),
                &now.to_string(),
                payload,
                &header,
                300,
                now,
            )
            .is_err(),
            "a payload lifted to another target must not verify"
        );

        // And a payload must not verify against a DIFFERENT CALL to the same target. This is
        // the property the per-call id exists for: `webhook-id` is the receiver's dedup
        // handle, so a constant one made every consultation after the first look like a
        // replay of the first, and a receiver following this repository's own guidance would
        // drop it or echo its cached first answer, bypassing the check with no attacker.
        assert!(
            ironauth_jose::webhooks::verify_delivery(
                std::slice::from_ref(&secret),
                &delivery_id(&signed_for.id, "call-two"),
                &now.to_string(),
                payload,
                &header,
                300,
                now,
            )
            .is_err(),
            "a captured delivery must not verify against a later consultation of the same \
             target, or a response can be replayed inside the tolerance window"
        );
    }

    /// An interruption with NOTHING to say is refused.
    ///
    /// The worst possible rejection: the flow stops, the form shows no error, and the person
    /// filling it in has no way to proceed and no idea why. Refused at construction rather
    /// than checked at render time, because by render time the flow has already stopped.
    #[test]
    fn an_interruption_must_carry_at_least_one_field_error() {
        assert!(
            TargetVerdict::interrupt(Vec::new()).is_err(),
            "an interruption with no field errors stops a flow and tells nobody why"
        );
        let verdict = TargetVerdict::interrupt(vec![FieldError {
            pointer: "/traits/email".to_owned(),
            message: "already registered".to_owned(),
        }])
        .expect("one error is enough");
        assert!(verdict.interrupts());
        assert!(!TargetVerdict::Allow.interrupts());
    }

    /// Pointers ESCAPE per RFC 6901, including the order-dependent pair.
    ///
    /// `~` must be substituted before `/`, or `~1` produced by escaping a slash is itself
    /// re-escaped into `~01` and the pointer resolves to nothing. A pointer that resolves to
    /// nothing surfaces as a validation error attached to no field, or to the wrong one --
    /// which is worse than no error, because the person sees a message next to an input that
    /// is fine.
    ///
    /// Delegated to `trait_schema`'s escaper rather than reimplemented, and asserted here so
    /// the delegation is measured rather than assumed.
    #[test]
    fn field_pointers_escape_per_rfc_6901() {
        assert_eq!(field_pointer(&["traits", "email"]), "/traits/email");
        assert_eq!(
            field_pointer(&["a/b"]),
            "/a~1b",
            "a slash inside a token is ~1"
        );
        assert_eq!(
            field_pointer(&["a~b"]),
            "/a~0b",
            "a tilde inside a token is ~0"
        );
        assert_eq!(
            field_pointer(&["a~/b"]),
            "/a~0~1b",
            "the tilde substitution runs FIRST; reversing the order yields ~01 and a pointer \
             that resolves to nothing"
        );
        assert_eq!(field_pointer(&[]), "", "no tokens is the whole document");
    }

    /// ONLY a sync pre-persist target runs before the write.
    ///
    /// Asserted over all four combinations rather than the one true case, because the value of
    /// this predicate is entirely in the cases it says NO to: an async target treated as
    /// blocking would block a flow on something nothing waits for.
    #[test]
    fn only_a_sync_pre_persist_target_runs_before_the_write() {
        assert!(target(Invocation::Sync, Timing::PrePersist).runs_before_write());
        assert!(!target(Invocation::Sync, Timing::PostPersist).runs_before_write());
        assert!(
            !target(Invocation::Async, Timing::PostPersist).runs_before_write(),
            "a fire-and-forget target must never make the flow wait for it"
        );
        assert!(
            !target(Invocation::Async, Timing::PrePersist).runs_before_write(),
            "the migration refuses this combination, and the predicate must not depend on \
             that: a rule enforced in only one place is a rule that breaks when the other \
             place changes"
        );
    }
}
