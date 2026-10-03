// SPDX-License-Identifier: MIT OR Apache-2.0

//! Required-channel reset mail aggregation. No logging fallback, plaintext queue,
//! automatic resend or credential mutation. Hosted routes are not mounted here.

use std::collections::BTreeSet;
use std::time::Duration;

use ironauth_store::{
    CorrelationId, IdentifierType, PasswordResetChallengeId, PasswordResetDelivery, StoreError,
    UserId, UserIdentifierRecord,
};

use crate::password_reset_smtp::{
    PasswordResetDeliveryFailure, PasswordResetMessage, PasswordResetNotice, PasswordResetTransport,
};
use crate::recovery::{RecoveryChannels, annotated_recovery_channels};
use crate::state::OidcState;

const MAX_CHANNELS: usize = 32;
const DELIVERY_BUDGET: Duration = Duration::from_secs(16);

/// One newly issued challenge and its transient mail content. The hosted caller
/// must supply the subject and primary address from successful store issuance,
/// never browser fields. No Debug or serialization on secret-bearing content.
pub struct ResetRequestDelivery<'a> {
    /// Store-resolved subject used to issue this challenge.
    pub subject: &'a UserId,
    /// Newly persisted, browser-bound challenge, used for one send attempt only.
    pub challenge: &'a PasswordResetChallengeId,
    /// Current verified primary address returned by reset issuance.
    pub primary_recipient: &'a str,
    /// Transient eight-digit reset code corresponding to the stored verifier.
    pub code: &'a str,
    /// Exact persisted challenge expiry.
    pub expires_at_unix_micros: i64,
    /// Actual cancellation capability for this challenge's recovery case.
    pub cancel_url: &'a str,
}

/// Read every currently required verified channel, perform one bounded send batch
/// and audit its terminal result. A logging sender cannot participate. Refusal of
/// any required channel prevents sending the primary code; uncertain acceptance
/// remains uncertain. Call once after successful issuance, never on page reads,
/// completion or an automatic retry. A persistence error must not resend mail.
///
/// # Errors
/// Foreign challenge scope or failure to persist the terminal outcome. Failure to
/// read/serve required channels is recorded as refusal, never partial acceptance.
pub async fn send_reset_request(
    state: &OidcState,
    request: &ResetRequestDelivery<'_>,
) -> Result<PasswordResetDelivery, StoreError> {
    let scope = request.subject.scope();
    if request.challenge.scope() != scope {
        return Err(StoreError::NotFound);
    }
    state
        .store()
        .scoped(scope)
        .acting(
            crate::interaction::user_actor(request.subject),
            CorrelationId::generate(state.env()),
        )
        .password_reset()
        .claim_delivery(state.env(), request.challenge, request.subject)
        .await?;
    let identifiers = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .list_for_user(request.subject)
        .await;
    let permitted = annotated_recovery_channels(state, scope).await;
    let plan = identifiers
        .ok()
        .and_then(|rows| select_channels(rows, permitted, request.primary_recipient));
    let mut accepted = 0;
    let outcome =
        if let (Some(channels), Some(transport)) = (plan, state.password_reset_transport()) {
            send_bounded(
                transport,
                request,
                &channels,
                &mut accepted,
                DELIVERY_BUDGET,
            )
            .await
        } else {
            PasswordResetDelivery::Refused
        };
    state
        .store()
        .scoped(scope)
        .acting(
            crate::interaction::user_actor(request.subject),
            CorrelationId::generate(state.env()),
        )
        .password_reset()
        .record_delivery(state.env(), request.challenge, outcome, accepted)
        .await?;
    Ok(outcome)
}

// Preflight the whole required set before sending any secret. An unsupported
// verified phone channel cannot silently disappear from an email-only recovery.
fn select_channels(
    rows: Vec<UserIdentifierRecord>,
    permitted: RecoveryChannels,
    primary: &str,
) -> Option<Vec<String>> {
    let canonical =
        |raw: &str| ironauth_store::identifier::canonicalize_identifier(IdentifierType::Email, raw);
    let primary_key = canonical(primary);
    if primary_key.is_empty() || !permitted.permits(IdentifierType::Email) {
        return None;
    }
    let mut seen = BTreeSet::new();
    let mut secondary = Vec::new();
    let mut primary_verified = false;
    for row in rows {
        if !row.verified || !permitted.permits(row.identifier_type) {
            continue;
        }
        if row.identifier_type != IdentifierType::Email {
            return None;
        }
        let key = canonical(&row.raw);
        if key.is_empty() {
            return None;
        }
        if !seen.insert(key.as_str().to_owned()) {
            continue;
        }
        if seen.len() > MAX_CHANNELS {
            return None;
        }
        if key == primary_key {
            primary_verified = true;
        } else {
            secondary.push(row.raw);
        }
    }
    primary_verified.then_some(secondary)
}

async fn send_bounded(
    transport: &dyn PasswordResetTransport,
    request: &ResetRequestDelivery<'_>,
    secondary: &[String],
    accepted: &mut u32,
    budget: Duration,
) -> PasswordResetDelivery {
    // A timed-out network attempt may have reached the relay. Keep acknowledged
    // prefix counts, but never claim overall acceptance or automatically resend.
    tokio::time::timeout(
        budget,
        send_channels(transport, request, secondary, accepted),
    )
    .await
    .unwrap_or(PasswordResetDelivery::Uncertain)
}

async fn send_channels(
    transport: &dyn PasswordResetTransport,
    request: &ResetRequestDelivery<'_>,
    secondary: &[String],
    accepted: &mut u32,
) -> PasswordResetDelivery {
    let mut outcome = PasswordResetDelivery::Accepted;
    for recipient in secondary {
        let result = transport
            .deliver(PasswordResetMessage {
                challenge_id: request.challenge,
                scope: request.subject.scope(),
                recipient,
                notice: PasswordResetNotice::Requested {
                    cancel_url: request.cancel_url,
                },
            })
            .await;
        accumulate(result, &mut outcome, accepted);
    }
    if outcome == PasswordResetDelivery::Accepted {
        let result = transport
            .deliver(PasswordResetMessage {
                challenge_id: request.challenge,
                scope: request.subject.scope(),
                recipient: request.primary_recipient,
                notice: PasswordResetNotice::Code {
                    code: request.code,
                    expires_at_unix_micros: request.expires_at_unix_micros,
                    cancel_url: request.cancel_url,
                },
            })
            .await;
        accumulate(result, &mut outcome, accepted);
    }
    outcome
}

fn accumulate(
    result: Result<(), PasswordResetDeliveryFailure>,
    outcome: &mut PasswordResetDelivery,
    accepted: &mut u32,
) {
    match result {
        Ok(()) => *accepted += 1,
        Err(PasswordResetDeliveryFailure::Uncertain) => *outcome = PasswordResetDelivery::Uncertain,
        Err(PasswordResetDeliveryFailure::Refused)
            if *outcome != PasswordResetDelivery::Uncertain =>
        {
            *outcome = PasswordResetDelivery::Refused;
        }
        Err(PasswordResetDeliveryFailure::Refused) => {}
    }
}

/// Durable worker for code-free completion warnings. It consumes only a scoped
/// challenge ID queued in the credential transaction; no reset secret is queued.
pub struct PasswordResetCompletionConsumer {
    state: OidcState,
}

impl PasswordResetCompletionConsumer {
    /// Use the same concrete SMTP configuration and scoped store as the provider.
    #[must_use]
    pub fn new(state: OidcState) -> Self {
        Self { state }
    }
}

impl ironauth_store::outbox::OutboxConsumer for PasswordResetCompletionConsumer {
    fn name(&self) -> &str {
        ironauth_store::PASSWORD_RESET_COMPLETION_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a ironauth_env::Env,
        scope: ironauth_store::Scope,
        message: &'a ironauth_store::OutboxMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), ironauth_store::outbox::ConsumerError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use ironauth_store::outbox::ConsumerError;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Payload {
                challenge_id: String,
            }
            let payload: Payload = serde_json::from_value(message.payload.clone())
                .map_err(|_| ConsumerError::permanent("reset_notice_invalid_payload"))?;
            let id = PasswordResetChallengeId::parse_in_scope(&payload.challenge_id, &scope)
                .map_err(|_| ConsumerError::permanent("reset_notice_invalid_scope"))?;
            deliver_completion_notice(&self.state, env, &id).await
        })
    }
}

fn notice_result(
    result: PasswordResetDelivery,
) -> Result<(), ironauth_store::outbox::ConsumerError> {
    use ironauth_store::outbox::ConsumerError;
    match result {
        PasswordResetDelivery::Accepted => Ok(()),
        PasswordResetDelivery::Refused => Err(ConsumerError::permanent("reset_notice_refused")),
        PasswordResetDelivery::Uncertain => {
            Err(ConsumerError::permanent("reset_notice_acceptance_unknown"))
        }
    }
}

async fn deliver_completion_notice(
    state: &OidcState,
    env: &ironauth_env::Env,
    id: &PasswordResetChallengeId,
) -> Result<(), ironauth_store::outbox::ConsumerError> {
    use ironauth_store::outbox::ConsumerError;
    if !state.password_recovery_delivery_available() {
        return Err(ConsumerError::retryable(
            "reset_notice_transport_unavailable",
        ));
    }
    let scope = id.scope();
    let acting = state.store().scoped(scope).acting(
        ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(env)),
        CorrelationId::generate(env),
    );
    let claim = acting
        .password_reset()
        .claim_completion_notice(env, id)
        .await
        .map_err(|_| ConsumerError::retryable("reset_notice_store_unavailable"))?;
    let Some(claim) = claim else {
        return resume_completion_notice(state, env, id).await;
    };
    let identifiers = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .list_for_user(&claim.subject)
        .await;
    let permitted = annotated_recovery_channels(state, scope).await;
    let plan = match (claim.recipient, identifiers) {
        (Some(primary), Ok(rows)) => {
            select_channels(rows, permitted, &primary).map(|mut secondary| {
                secondary.push(primary);
                secondary
            })
        }
        _ => None,
    };
    let mut accepted = 0;
    let outcome =
        if let (Some(channels), Some(transport)) = (plan, state.password_reset_transport()) {
            tokio::time::timeout(DELIVERY_BUDGET, async {
                let mut outcome = PasswordResetDelivery::Accepted;
                for recipient in channels {
                    let result = transport
                        .deliver(PasswordResetMessage {
                            challenge_id: id,
                            scope,
                            recipient: &recipient,
                            notice: PasswordResetNotice::Completed,
                        })
                        .await;
                    accumulate(result, &mut outcome, &mut accepted);
                }
                outcome
            })
            .await
            .unwrap_or(PasswordResetDelivery::Uncertain)
        } else {
            PasswordResetDelivery::Refused
        };
    acting
        .password_reset()
        .record_completion_notice(env, id, outcome, accepted)
        .await
        .map_err(|_| ConsumerError::retryable("reset_notice_result_unconfirmed"))?;
    notice_result(outcome)
}

// A worker retry can finish store bookkeeping, but never repeat an external send.
// Let an overlapping attempt finish its bounded SMTP batch before classifying a
// stale claim as unknown. A lost result can never be relabelled accepted here.
async fn resume_completion_notice(
    state: &OidcState,
    env: &ironauth_env::Env,
    id: &PasswordResetChallengeId,
) -> Result<(), ironauth_store::outbox::ConsumerError> {
    use ironauth_store::outbox::ConsumerError;
    let scoped = state.store().scoped(id.scope());
    let status = scoped
        .password_reset()
        .completion_notice_status(id)
        .await
        .map_err(|_| ConsumerError::retryable("reset_notice_store_unavailable"))?
        .ok_or_else(|| ConsumerError::permanent("reset_notice_not_due"))?;
    if let Some(result) = status.result {
        return notice_result(result);
    }
    let now = crate::util::epoch_micros(env.clock().now_utc());
    let Some(started) = status.started_at_unix_micros else {
        return Err(ConsumerError::retryable("reset_notice_not_claimed"));
    };
    if now.saturating_sub(started) < 30_000_000 {
        return Err(ConsumerError::retryable("reset_notice_in_progress"));
    }
    scoped
        .acting(
            ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(env)),
            CorrelationId::generate(env),
        )
        .password_reset()
        .record_completion_notice(env, id, PasswordResetDelivery::Uncertain, 0)
        .await
        .map_err(|_| ConsumerError::retryable("reset_notice_result_unconfirmed"))?;
    notice_result(PasswordResetDelivery::Uncertain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, Scope, TenantId, UserIdentifierId};
    use std::sync::Mutex;

    fn scope(env: &Env) -> Scope {
        Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
    }
    fn row(
        env: &Env,
        scope: Scope,
        raw: &str,
        kind: IdentifierType,
        verified: bool,
    ) -> UserIdentifierRecord {
        UserIdentifierRecord {
            id: UserIdentifierId::generate(env, &scope),
            identifier_type: kind,
            raw: raw.to_owned(),
            verified,
        }
    }

    #[test]
    fn channel_selection_requires_verified_primary_and_every_supported_required_channel() {
        let env = Env::system();
        let scope = scope(&env);
        let owner = row(
            &env,
            scope,
            "Owner@example.test",
            IdentifierType::Email,
            true,
        );
        let secondary = row(
            &env,
            scope,
            "backup@example.test",
            IdentifierType::Email,
            true,
        );
        let unverified = row(
            &env,
            scope,
            "unverified@example.test",
            IdentifierType::Email,
            false,
        );
        assert_eq!(
            select_channels(
                vec![owner.clone(), secondary.clone(), secondary, unverified],
                RecoveryChannels::Any,
                "owner@example.test"
            ),
            Some(vec!["backup@example.test".into()])
        );
        assert!(select_channels(vec![], RecoveryChannels::Any, "owner@example.test").is_none());
        let phone = row(&env, scope, "+15555550101", IdentifierType::Phone, true);
        assert!(
            select_channels(
                vec![owner.clone(), phone.clone()],
                RecoveryChannels::Any,
                "owner@example.test"
            )
            .is_none()
        );
        assert_eq!(
            select_channels(
                vec![owner.clone(), phone],
                RecoveryChannels::Only {
                    email: true,
                    phone: false
                },
                "owner@example.test"
            ),
            Some(vec![])
        );
        assert!(
            select_channels(
                vec![owner.clone()],
                RecoveryChannels::Only {
                    email: false,
                    phone: true
                },
                "owner@example.test"
            )
            .is_none()
        );
        let mut oversized = vec![owner];
        for i in 0..MAX_CHANNELS {
            oversized.push(row(
                &env,
                scope,
                &format!("backup{i}@example.test"),
                IdentifierType::Email,
                true,
            ));
        }
        assert!(select_channels(oversized, RecoveryChannels::Any, "owner@example.test").is_none());
    }

    struct Fixture {
        replies: Mutex<std::collections::VecDeque<Result<(), PasswordResetDeliveryFailure>>>,
        sent: Mutex<Vec<(String, &'static str)>>,
    }
    #[async_trait::async_trait]
    impl PasswordResetTransport for Fixture {
        async fn deliver(
            &self,
            message: PasswordResetMessage<'_>,
        ) -> Result<(), PasswordResetDeliveryFailure> {
            let purpose = match message.notice {
                PasswordResetNotice::Code { .. } => "code",
                PasswordResetNotice::Requested { .. } => "notice",
                PasswordResetNotice::Completed => "completed",
            };
            self.sent
                .lock()
                .unwrap()
                .push((message.recipient.to_owned(), purpose));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("one attempt per planned send")
        }
    }

    #[tokio::test]
    async fn all_notices_must_be_accepted_before_primary_code_and_uncertainty_is_retained() {
        let env = Env::system();
        let scope = scope(&env);
        let subject = UserId::generate(&env, &scope);
        let challenge = PasswordResetChallengeId::generate(&env, &scope);
        let request = ResetRequestDelivery {
            subject: &subject,
            challenge: &challenge,
            primary_recipient: "owner@example.test",
            code: "12345678",
            expires_at_unix_micros: 1,
            cancel_url: "https://auth.example.test/recover/cancel?token=fixture",
        };
        for (replies, expected, accepted_count) in [
            (
                vec![Ok(()), Ok(()), Ok(())],
                PasswordResetDelivery::Accepted,
                3,
            ),
            (
                vec![Err(PasswordResetDeliveryFailure::Refused), Ok(())],
                PasswordResetDelivery::Refused,
                1,
            ),
            (
                vec![
                    Err(PasswordResetDeliveryFailure::Uncertain),
                    Err(PasswordResetDeliveryFailure::Refused),
                ],
                PasswordResetDelivery::Uncertain,
                0,
            ),
            (
                vec![Ok(()), Ok(()), Err(PasswordResetDeliveryFailure::Uncertain)],
                PasswordResetDelivery::Uncertain,
                2,
            ),
        ] {
            let expected_sends = replies.len();
            let fixture = Fixture {
                replies: Mutex::new(replies.into()),
                sent: Mutex::new(Vec::new()),
            };
            let mut accepted = 0;
            let outcome = send_channels(
                &fixture,
                &request,
                &["backup1@example.test".into(), "backup2@example.test".into()],
                &mut accepted,
            )
            .await;
            assert_eq!(outcome, expected);
            assert_eq!(accepted, accepted_count);
            let sent = fixture.sent.lock().unwrap();
            assert_eq!(sent.len(), expected_sends);
            assert_eq!(sent[0].1, "notice");
            assert_eq!(sent[1].1, "notice");
            if sent.len() == 3 {
                assert_eq!(sent[2], ("owner@example.test".into(), "code"));
            }
        }
    }

    struct StalledNotice(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl PasswordResetTransport for StalledNotice {
        async fn deliver(
            &self,
            _: PasswordResetMessage<'_>,
        ) -> Result<(), PasswordResetDeliveryFailure> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                std::future::pending().await
            }
        }
    }

    #[tokio::test]
    async fn batch_timeout_keeps_accepted_prefix_and_never_sends_code_or_retries() {
        let env = Env::system();
        let scope = scope(&env);
        let subject = UserId::generate(&env, &scope);
        let challenge = PasswordResetChallengeId::generate(&env, &scope);
        let request = ResetRequestDelivery {
            subject: &subject,
            challenge: &challenge,
            primary_recipient: "owner@example.test",
            code: "12345678",
            expires_at_unix_micros: 1,
            cancel_url: "https://auth.example.test/recover/cancel?token=fixture",
        };
        let fixture = StalledNotice(std::sync::atomic::AtomicUsize::new(0));
        let mut accepted = 0;
        let outcome = send_bounded(
            &fixture,
            &request,
            &["backup1@example.test".into(), "backup2@example.test".into()],
            &mut accepted,
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(outcome, PasswordResetDelivery::Uncertain);
        assert_eq!(accepted, 1);
        assert_eq!(fixture.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
