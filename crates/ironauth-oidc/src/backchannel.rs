// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID Connect Back-Channel Logout 1.0: the Logout Token and the delivery worker
//! (issue #34).
//!
//! Back-Channel Logout is the ONE logout-propagation mechanism that survived
//! third-party-cookie deprecation: when an SSO session ends (an RP logout #33, an admin
//! revoke, a global revoke) the OP sends a signed Logout Token, out of band of any
//! browser, to each participating relying party's registered `backchannel_logout_uri`.
//! Every rule here is a spec-compliance or an operability defense:
//!
//! - **The Logout Token is a signed JWT (OIDC Back-Channel Logout 2.4).** It carries
//!   `iss`, `aud` (the RP's client id), `iat`, `exp` (the hydra#4035 REQUIRED-claim bug),
//!   `jti`, the `events` member naming the back-channel-logout event, and `sid`. It is
//!   minted through the SAME ironauth-jose signing core and per-environment key as an ID
//!   token, with the header `typ = logout+jwt`, and it MUST NOT carry a `nonce`.
//!
//! - **One token per (client, session), each with its OWN `sid`.** This OP is session
//!   based, so `sid` is REQUIRED and is the per-(client, session) value from #32 (never
//!   the raw session id). An RP only ever learns its own `sid`; a full-user logout across
//!   N pairs emits N tokens, avoiding the keycloak#22914 ambiguous sub-only token.
//!
//! - **Delivery is a distributed-systems problem, so it is a WORKER, not a request-path
//!   POST.** RPs are down, slow, or misconfigured. Delivery therefore runs off the
//!   generic outbox consumer framework (#104) as TWO registered consumers, and the split
//!   is the safety property: [`SessionEndedExplodeConsumer`] turns one ended session into
//!   one outbox message PER participating relying party, and
//!   [`BackChannelLogoutConsumer`] handles exactly ONE of those, sending the token
//!   through the SSRF-hardened outbound fetcher (the `backchannel_logout_uri` is an
//!   RP-controlled URL, an SSRF vector). A failure is retried with the substrate's
//!   bounded exponential backoff up to its attempts cap, then dead-lettered with its last
//!   error. A slow or failing RP never blocks the others (each delivery is its own
//!   message, in its own singleton ordering group) or wedges a worker (a per-delivery
//!   timeout via the fetcher caps). Delivery is at-least-once; the RP dedups on `jti`.
//!
//! ## Why two consumers and not one
//!
//! Fusing the fan-out and the delivery into one handler would give N relying parties a
//! SHARED attempts counter: one dead RP would burn the attempts of a message that also
//! carries the healthy RPs, and the dead-letter would take the whole session's logout
//! with it, including the RPs that would have succeeded. That is a lost logout, so the
//! per-RP isolation stated at the top of this module is structural rather than a
//! best-effort property, and it is a message boundary that keeps it so.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_jose::{EmissionOptions, TokenTyp, sign_jws_with_policy};
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    BACKCHANNEL_LOGOUT_CONSUMER, IssuedTokenId, NewOutboxMessage, OutboxMessage,
    SESSION_ENDED_CONSUMER, Scope, SessionId, Store,
};
use serde_json::json;

use crate::issuer::IssuerRegistry;

/// The `events` member value: the back-channel-logout event URI mapping to an empty
/// object (OIDC Back-Channel Logout 2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The Logout Token header `typ` (OIDC Back-Channel Logout 2.4).
///
/// Read from the ONE ironauth-jose declaration rather than spelled again here, so
/// this constant and the media type the mint actually stamps cannot drift apart:
/// they are the same bytes, not two literals that agree today.
pub const LOGOUT_TOKEN_TYP: &str = TokenTyp::LogoutToken.media_type();

/// The Logout Token lifetime: short, because it is a one-shot notification the RP acts on
/// immediately (and dedups on `jti`), never a bearer credential it stores.
const LOGOUT_TOKEN_TTL: Duration = Duration::from_secs(120);

/// Build the Logout Token claim set (OIDC Back-Channel Logout 2.4). Pure, so the claim
/// shape is unit-tested without a signer or a store.
///
/// Carries exactly the REQUIRED claims plus `sid`: `iss`, `aud` (the RP client id),
/// `iat`, `exp`, `jti`, the `events` member, and `sid` (this session-based OP always
/// sends the per-(client, session) value). It deliberately carries NO `nonce` (2.4
/// forbids it) and no `sub` (sid alone identifies the session, avoiding the ambiguous
/// sub-only token).
#[must_use]
pub fn build_logout_token_claims(
    issuer: &str,
    client_id: &str,
    sid: &str,
    jti: &str,
    iat: i64,
    exp: i64,
) -> serde_json::Value {
    json!({
        "iss": issuer,
        "aud": client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        "sid": sid,
    })
}

/// Why a single Logout Token POST did not succeed. Uniform, non-secret reasons so the
/// recorded `last_error` never becomes an oracle for internal topology (the fetcher's
/// own [`ironauth_fetch::FetchError::Blocked`] is already uniform).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// The destination was refused by the outbound SSRF policy (a loopback, private, or
    /// metadata address behind the RP-controlled URL).
    Blocked,
    /// The delivery exceeded its per-delivery time budget.
    Timeout,
    /// The RP answered with a non-2xx status.
    Status(u16),
    /// The connection or exchange failed at the transport layer, or the URL was
    /// malformed.
    Transport,
}

impl SendFailure {
    /// A stable, bounded label recorded as the delivery's `last_error`.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            SendFailure::Blocked => "blocked_by_ssrf_policy".to_owned(),
            SendFailure::Timeout => "timeout".to_owned(),
            SendFailure::Status(status) => format!("http_status_{status}"),
            SendFailure::Transport => "transport_error".to_owned(),
        }
    }
}

/// The outbound seam a Logout Token is delivered through. The production implementor
/// wraps the SSRF-hardened [`ironauth_fetch::Fetcher`]; a test implementor records the
/// tokens and returns programmable outcomes without any network.
///
/// The returned future is declared `Send` so a worker built on this seam stays spawnable
/// on a multi-threaded runtime.
pub trait LogoutSender: Send + Sync {
    /// POST `logout_token` (form-encoded) to the RP's `uri`, returning `Ok(())` on a 2xx
    /// and a [`SendFailure`] otherwise. Delivering through this method is the ONLY
    /// outbound path the worker has; the production implementor routes it through
    /// ironauth-fetch so the SSRF hardening always applies.
    fn deliver(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> impl Future<Output = Result<(), SendFailure>> + Send;
}

/// The production Logout Token sender: a POST through the SSRF-hardened outbound fetcher
/// (issue #34, invariant: outbound HTTP only via ironauth-fetch).
///
/// The RP-controlled `backchannel_logout_uri` is an SSRF vector, so every delivery goes
/// through [`ironauth_fetch::Fetcher::fetch`], which resolves-once-pins, denies internal
/// resolved addresses, follows no redirects, and enforces size and time caps. A 2xx is a
/// success; anything else (a non-2xx status, a blocked destination, a timeout, a
/// transport error) is a [`SendFailure`] the worker retries or dead-letters.
pub struct FetchLogoutSender {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl FetchLogoutSender {
    /// Wrap a shared hardened fetcher.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }

    /// Build a production sender whose per-delivery time budget is `total_timeout` (the
    /// SSRF-hardened fetcher aborts a delivery that exceeds it, so a slow RP cannot wedge
    /// the worker). Constructs the one sanctioned outbound fetcher internally, so the
    /// binary wiring the worker does not itself reach an HTTP-client crate.
    ///
    /// # Errors
    ///
    /// [`ironauth_fetch::TlsSetupError`] if the OS trust store yields no usable roots.
    pub fn with_timeout(total_timeout: Duration) -> Result<Self, ironauth_fetch::TlsSetupError> {
        let limits = ironauth_fetch::FetchLimits {
            total_timeout,
            ..ironauth_fetch::FetchLimits::default()
        };
        let fetcher = ironauth_fetch::Fetcher::new(limits)?;
        Ok(Self::new(Arc::new(fetcher)))
    }
}

impl LogoutSender for FetchLogoutSender {
    fn deliver(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> impl Future<Output = Result<(), SendFailure>> + Send {
        // The application/x-www-form-urlencoded body: the single `logout_token`
        // parameter (OIDC Back-Channel Logout 2.5).
        let body = serde_urlencoded::to_string([("logout_token", logout_token)]);
        let uri = uri.to_owned();
        let fetcher = Arc::clone(&self.fetcher);
        async move {
            let Ok(body) = body else {
                return Err(SendFailure::Transport);
            };
            let request = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::WebhookDelivery,
                http::Method::POST,
                uri,
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(body);
            match fetcher.fetch(request).await {
                Ok(response) if response.status().is_success() => Ok(()),
                Ok(response) => Err(SendFailure::Status(response.status().as_u16())),
                Err(ironauth_fetch::FetchError::Blocked) => Err(SendFailure::Blocked),
                Err(ironauth_fetch::FetchError::Timeout) => Err(SendFailure::Timeout),
                Err(_) => Err(SendFailure::Transport),
            }
        }
    }
}

/// The payload key naming the ended SSO session, written by the session-ended producer
/// and read by [`SessionEndedExplodeConsumer`].
const PAYLOAD_SESSION_ID: &str = "session_id";
/// The payload key naming the target relying party on a per-RP delivery message.
const PAYLOAD_CLIENT_ID: &str = "client_id";
/// The payload key carrying THAT client's own per-(client, session) `sid`.
const PAYLOAD_SID: &str = "sid";
/// The payload key carrying the RP's registered `backchannel_logout_uri`, snapshotted at
/// explode time.
const PAYLOAD_LOGOUT_URI: &str = "logout_uri";
/// The payload key carrying the Logout Token `jti`, minted once at explode time.
const PAYLOAD_JTI: &str = "jti";

/// The `last_error` label recorded when a message's payload cannot be read. Bounded and
/// non-secret, like every other label, and PERMANENT: no further attempt can make an
/// unreadable body readable.
const MALFORMED_PAYLOAD_LABEL: &str = "malformed_payload";

/// The `last_error` label recorded when a persistence fault interrupts a handler.
/// Retryable: the queue still holds the work and the next attempt re-runs it.
const STORE_ERROR_LABEL: &str = "store_error";

/// Read a required string field off a message payload.
fn payload_str<'a>(message: &'a OutboxMessage, key: &str) -> Result<&'a str, ConsumerError> {
    message
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))
}

/// The idempotency key AND the ordering key of ONE per-RP delivery: the (session, client)
/// pair it notifies.
///
/// The two being the SAME value is the decision that keeps a dead RP from delaying a live
/// one, and it is worth stating why the obvious alternative is worse. Keying the ORDER on
/// the client id would put every logout bound for one RP into a single group, and the
/// substrate leases only a group's HEAD; one unreachable RP would then stall every
/// subsequent logout to that RP, for every user, for the whole backoff schedule, and the
/// stall would be invisible because the messages behind the head are not failing, merely
/// never claimed. A per-message key makes every group a SINGLETON and removes the
/// head-of-group predicate entirely.
///
/// Nothing is given up by not ordering these. Two Logout Tokens for one RP name different
/// sessions through their own `sid` and carry no `sub`, so they commute: an RP that
/// applies them in either order ends the same two sessions.
fn delivery_key(session_id: &str, client_id: &str) -> String {
    format!("{session_id}:{client_id}")
}

/// The FAN-OUT consumer (issue #104): one ended SSO session becomes one per-RP delivery
/// message, and nothing more.
///
/// It registers under [`SESSION_ENDED_CONSUMER`], which is the discriminator the session
/// flip writes inside its own transaction, and produces under
/// [`BACKCHANNEL_LOGOUT_CONSUMER`]. Both names come from the ONE exported constant each,
/// never a literal spelled here: a consumer whose name does not match its producers'
/// discriminator drains nothing at all and reports perfect health while doing it.
///
/// # Why the fan-out is a CONSUMER and not part of the session-end transaction
///
/// Moving it into the producer would put an unbounded per-client query and N inserts
/// inside the transaction that ends a session, which is on the hot path of every logout
/// and every revoke, and it would make the cost of ending one session scale with how many
/// relying parties that user ever logged into. It would also leave `session_ended`
/// without a consumer, so its messages would accumulate forever in a table that has no
/// reaper and grants no role DELETE.
///
/// # Idempotence, which is what makes a lapsed lease harmless
///
/// The handler is re-run whenever its lease lapses mid-explode, so it MUST tolerate
/// finding its own earlier output. It does, through
/// [`OutboxRepo::enqueue_all`](ironauth_store::OutboxRepo::enqueue_all), which skips an
/// existing `(consumer, idempotency_key)` instead of raising. Looping the raising
/// `enqueue` here would instead fail the re-explode with a unique violation, fail
/// identically on every retry, and DEAD-LETTER this session's fan-out with every RP the
/// first pass had not yet reached left permanently un-notified.
///
/// A consequence worth naming: the `jti` is minted at explode time and lives in the
/// message payload, which is immutable once written. A re-explode mints a fresh id and
/// then DISCARDS it, because the conflicting insert does nothing, so every attempt of a
/// delivery re-POSTs a token bearing the same `jti` and the RP's dedup holds.
pub struct SessionEndedExplodeConsumer {
    store: Store,
}

impl SessionEndedExplodeConsumer {
    /// Explode ended sessions found on the data-plane `store` into per-RP deliveries.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Resolve the participants of ONE ended session and enqueue one delivery message
    /// each. Returns how many were NEWLY enqueued (zero on a re-run that finds them all).
    async fn explode(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<u64, ConsumerError> {
        let session_text = payload_str(message, PAYLOAD_SESSION_ID)?;
        // A session id that does not parse in this scope can never parse in it, so this
        // is permanent: retrying would burn the attempts cap to reach the same dead
        // letter.
        let session_id = SessionId::parse_in_scope(session_text, &scope)
            .map_err(|_| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        let scoped = self.store.scoped(scope);
        let participants = scoped
            .client_sessions()
            .backchannel_participants(&session_id)
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))?;
        // The keys are built first and borrowed by the messages, because
        // `NewOutboxMessage` holds `&str` and the fan-out must be ONE slice so it commits
        // atomically.
        let keys: Vec<String> = participants
            .iter()
            .map(|rp| delivery_key(session_text, &rp.client_id))
            .collect();
        let payloads: Vec<serde_json::Value> = participants
            .iter()
            .map(|rp| {
                json!({
                    PAYLOAD_SESSION_ID: session_text,
                    PAYLOAD_CLIENT_ID: rp.client_id,
                    PAYLOAD_SID: rp.sid,
                    PAYLOAD_LOGOUT_URI: rp.logout_uri,
                    // Minted HERE, once, and carried on the immutable payload, so every
                    // attempt of this delivery presents the identical jti.
                    PAYLOAD_JTI: IssuedTokenId::generate(env, &scope).to_string(),
                })
            })
            .collect();
        let messages: Vec<NewOutboxMessage<'_>> = keys
            .iter()
            .zip(payloads)
            .map(|(key, payload)| NewOutboxMessage {
                consumer: BACKCHANNEL_LOGOUT_CONSUMER,
                idempotency_key: key,
                // The SAME value as the idempotency key: a singleton ordering group per
                // delivery, so no RP can ever be behind another in a queue.
                ordering_key: key,
                payload,
            })
            .collect();
        scoped
            .outbox()
            .enqueue_all(env, &messages)
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))
    }
}

impl OutboxConsumer for SessionEndedExplodeConsumer {
    fn name(&self) -> &str {
        SESSION_ENDED_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move {
            self.explode(env, scope, message).await?;
            Ok(())
        })
    }
}

/// The DELIVERY consumer (issue #104): exactly ONE relying party's Logout Token POST.
///
/// It registers under [`BACKCHANNEL_LOGOUT_CONSUMER`], the name
/// [`SessionEndedExplodeConsumer`] produces under, read from the same exported constant.
/// It is generic over [`LogoutSender`] so the network is injectable; production passes
/// [`FetchLogoutSender`], which routes every POST through the SSRF-hardened fetcher.
///
/// One message is one recipient, so a dead RP consumes only its OWN attempts and
/// dead-letters only its OWN delivery. The substrate owns the backoff schedule, the
/// attempts cap and the dead-letter, which is why this type has no retry arithmetic of
/// its own.
///
/// Delivery is at-least-once: a handler that POSTs and then loses its lease before the
/// completion is recorded is re-run, and the RP sees the same token twice. That is the
/// contract, and the stable `jti` on the immutable payload is what makes it safe.
pub struct BackChannelLogoutConsumer<S> {
    issuers: Arc<IssuerRegistry>,
    sender: S,
}

impl<S: LogoutSender> BackChannelLogoutConsumer<S> {
    /// Build a delivery consumer over the shared issuer registry (for the per-environment
    /// signing key and issuer string) and a `sender`.
    ///
    /// It deliberately holds NO environment seam of its own. The clock it stamps `iat` and
    /// `exp` from is the one the WORKER hands to
    /// [`handle`](OutboxConsumer::handle), which is the same seam the queue reads its
    /// visibility lease and backoff gate from. A stored second copy could be a different
    /// `Env` from the worker's, and the symptom would be logout tokens minted against a
    /// clock the queue does not share.
    #[must_use]
    pub fn new(issuers: Arc<IssuerRegistry>, sender: S) -> Self {
        Self { issuers, sender }
    }

    /// Build and sign the Logout Token for one (client, session) pair, through the SAME
    /// per-environment issuer/key and ironauth-jose core an ID token uses. The `jti` is
    /// the delivery message's OWN, minted once at explode time and carried on its
    /// immutable payload, so a retry re-POSTs the SAME token and the RP dedups on it.
    async fn build_token(
        &self,
        env: &Env,
        scope: Scope,
        client_id: &str,
        sid: &str,
        jti: &str,
    ) -> Result<String, SendFailure> {
        let now = env.clock().now_utc();
        let entry = self
            .issuers
            .entry_for(&scope, now)
            .await
            .ok_or(SendFailure::Transport)?;
        let signer = entry.signer(now).ok_or(SendFailure::Transport)?;
        let policy = entry.policy();
        let issuer = self.issuers.issuer_for(&scope);
        let iat = unix_secs(now);
        let exp = iat.saturating_add(secs_i64(LOGOUT_TOKEN_TTL));
        let claims = build_logout_token_claims(&issuer, client_id, sid, jti, iat, exp);
        let payload = serde_json::to_vec(&claims).map_err(|_| SendFailure::Transport)?;
        sign_jws_with_policy(
            policy,
            signer,
            &payload,
            &EmissionOptions::new().with_token_typ(TokenTyp::LogoutToken),
        )
        .map_err(|_| SendFailure::Transport)
    }

    /// Deliver ONE message: read the recipient off the payload, mint its token, POST it.
    async fn deliver_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let client_id = payload_str(message, PAYLOAD_CLIENT_ID)?;
        let sid = payload_str(message, PAYLOAD_SID)?;
        let logout_uri = payload_str(message, PAYLOAD_LOGOUT_URI)?;
        let jti = payload_str(message, PAYLOAD_JTI)?;
        let token = self
            .build_token(env, scope, client_id, sid, jti)
            .await
            // Every mint failure is RETRYABLE, because a mint that failed once can
            // succeed later (an environment whose signing key is not provisioned yet, a
            // control-plane read that did not answer) and treating it as permanent would
            // discard the logout on one unlucky pass.
            //
            // "A later attempt fixes it" is true only while attempts REMAIN, and that is
            // worth stating rather than implying: the budget is finite, so any cause that
            // outlasts the backoff schedule ends in a dead letter, not in a fix. The one
            // cause that reliably outlasts it was a SUSPENDED environment, whose every
            // mint fails for as long as the suspension lasts; that case no longer reaches
            // this line, because a fenced scope is skipped before its messages are
            // claimed (`OutboxWorker::run_once_until`).
            .map_err(|failure| ConsumerError::retryable(failure.label()))?;
        self.sender
            .deliver(logout_uri, &token)
            .await
            // A refused destination, a timeout, a non-2xx and a transport fault are all
            // retryable: the substrate's finite attempts cap is what turns a persistently
            // dead RP into a dead letter, so nothing here needs a second way to give up.
            .map_err(|failure| ConsumerError::retryable(failure.label()))
    }
}

impl<S: LogoutSender> OutboxConsumer for BackChannelLogoutConsumer<S> {
    fn name(&self) -> &str {
        BACKCHANNEL_LOGOUT_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.deliver_one(env, scope, message).await })
    }
}

/// Seconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Whole seconds of a duration as an `i64` (saturating).
fn secs_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_token_claims_carry_the_required_set_and_no_nonce() {
        let claims = build_logout_token_claims(
            "https://op.example/t/ten_a/e/env_b",
            "cli_rp",
            "sid_abc",
            "tok_jti",
            1_000,
            1_120,
        );
        assert_eq!(claims["iss"], "https://op.example/t/ten_a/e/env_b");
        assert_eq!(claims["aud"], "cli_rp");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_120);
        assert_eq!(claims["jti"], "tok_jti");
        assert_eq!(claims["sid"], "sid_abc");
        // The events member names the back-channel-logout event and maps to an empty
        // object (OIDC Back-Channel Logout 2.4).
        assert_eq!(claims["events"][BACKCHANNEL_LOGOUT_EVENT], json!({}));
        // A Logout Token MUST NOT carry a nonce, and this session-based OP omits sub.
        assert!(claims.get("nonce").is_none(), "a logout token has no nonce");
        assert!(
            claims.get("sub").is_none(),
            "sid alone identifies the session"
        );
    }

    #[test]
    fn send_failure_labels_are_bounded_and_non_secret() {
        assert_eq!(SendFailure::Blocked.label(), "blocked_by_ssrf_policy");
        assert_eq!(SendFailure::Timeout.label(), "timeout");
        assert_eq!(SendFailure::Status(503).label(), "http_status_503");
        assert_eq!(SendFailure::Transport.label(), "transport_error");
    }
}
