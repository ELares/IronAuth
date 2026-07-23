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
//!   POST.** RPs are down, slow, or misconfigured. The worker drains the durable
//!   session-ended outbox (#35), EXPLODES each ended session into one per-RP delivery,
//!   and POSTs the token through the SSRF-hardened outbound fetcher (the
//!   `backchannel_logout_uri` is an RP-controlled URL, an SSRF vector). A failure is
//!   retried with bounded exponential backoff (its schedule and jitter drawn from the
//!   deterministic clock and entropy seams) up to an attempts cap, then dead-lettered
//!   with its last error. A slow or failing RP never blocks the others (each delivery is
//!   its own row) or wedges the worker (a per-delivery timeout via the fetcher caps).
//!   Delivery is at-least-once; the RP dedups on `jti`.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_jose::{EmissionOptions, sign_jws_with_policy};
use ironauth_store::{Scope, Store};
use serde_json::json;

use crate::issuer::IssuerRegistry;

/// The `events` member value: the back-channel-logout event URI mapping to an empty
/// object (OIDC Back-Channel Logout 2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The Logout Token header `typ` (OIDC Back-Channel Logout 2.4).
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";

/// The Logout Token lifetime: short, because it is a one-shot notification the RP acts on
/// immediately (and dedups on `jti`), never a bearer credential it stores.
const LOGOUT_TOKEN_TTL: Duration = Duration::from_secs(120);

/// The largest backoff, in seconds, any single retry waits: caps the exponential growth
/// so a long attempts cap can never schedule an absurd or overflowing delay.
const MAX_BACKOFF_SECS: u64 = 86_400;

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

/// The tuning knobs for the delivery worker (issue #34), sourced from `OidcConfig`.
#[derive(Debug, Clone, Copy)]
pub struct WorkerSettings {
    /// The maximum number of delivery attempts before a delivery is dead-lettered.
    pub max_attempts: u32,
    /// The base delay for the exponential backoff between retries.
    pub retry_base: Duration,
    /// The visibility lease a claim stamps (a crashed worker's delivery reappears once
    /// this lapses).
    pub lease: Duration,
    /// The maximum number of rows claimed per drain pass, for both the explode and the
    /// deliver stage.
    pub batch: i64,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            retry_base: Duration::from_secs(10),
            lease: Duration::from_secs(30),
            batch: 64,
        }
    }
}

/// The outcome of one drain pass, for observability and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainStats {
    /// Session-ended outbox events exploded into per-RP deliveries this pass.
    pub events_exploded: u64,
    /// Per-RP deliveries that succeeded (a 2xx) this pass.
    pub delivered: u64,
    /// Deliveries that failed and were scheduled for a backoff retry this pass.
    pub retried: u64,
    /// Deliveries that reached the attempts cap and were dead-lettered this pass.
    pub dead_lettered: u64,
}

/// The OIDC Back-Channel Logout delivery worker (issue #34).
///
/// It consumes the durable session-ended outbox (#35) as the source of truth for "a
/// session ended, fan out", resolves the participating relying parties per (client,
/// session), builds each RP its OWN signed Logout Token, and delivers it through the
/// injected [`LogoutSender`] (production: the SSRF-hardened fetcher). It is generic over
/// the sender so the network is injectable in tests. Multiple workers or replicas are
/// safe: every claim is `FOR UPDATE SKIP LOCKED`.
pub struct BackChannelLogoutWorker<S> {
    store: Store,
    env: Env,
    issuers: Arc<IssuerRegistry>,
    sender: S,
    settings: WorkerSettings,
}

impl<S: LogoutSender> BackChannelLogoutWorker<S> {
    /// Build a worker over the data-plane `store`, the environment seam, the shared
    /// issuer registry (for the per-environment signing key and issuer string), a
    /// `sender`, and the tuning `settings`.
    #[must_use]
    pub fn new(
        store: Store,
        env: Env,
        issuers: Arc<IssuerRegistry>,
        sender: S,
        settings: WorkerSettings,
    ) -> Self {
        Self {
            store,
            env,
            issuers,
            sender,
            settings,
        }
    }

    /// Run ONE drain pass for `scope`: explode any newly-drained session-ended events
    /// into per-RP deliveries, then attempt every due delivery. Returns the per-pass
    /// statistics. A production loop calls this on a cadence per scope; a test calls it
    /// directly, advancing the manual clock to exercise the backoff schedule.
    ///
    /// # Errors
    ///
    /// [`ironauth_store::StoreError`] on a persistence fault; a single RP's delivery
    /// failure is NOT an error (it is retried or dead-lettered), so a failing RP never
    /// aborts the pass or blocks the others.
    pub async fn run_once(&self, scope: Scope) -> Result<DrainStats, ironauth_store::StoreError> {
        let mut stats = DrainStats::default();
        self.explode(scope, &mut stats).await?;
        self.deliver(scope, &mut stats).await?;
        Ok(stats)
    }

    /// The explode stage: claim newly-visible session-ended events off the #35 outbox and
    /// fan each into one per-RP delivery row, then mark the outbox event delivered so it
    /// never drains again. The explode is idempotent (a redelivered outbox event queues
    /// no duplicate deliveries), so marking the event delivered only after the deliveries
    /// are durably queued is safe.
    async fn explode(
        &self,
        scope: Scope,
        stats: &mut DrainStats,
    ) -> Result<(), ironauth_store::StoreError> {
        let scoped = self.store.scoped(scope);
        let events = scoped
            .session_events()
            .claim(&self.env, self.settings.lease, self.settings.batch)
            .await?;
        for event in &events {
            scoped
                .backchannel_deliveries()
                .enqueue_for_event(&self.env, &event.id, &event.session_id)
                .await?;
            // The deliveries are durably queued; retire the outbox event. Idempotent, so
            // a re-drain before this mark simply re-explodes into the same rows.
            scoped
                .session_events()
                .mark_delivered(&self.env, &event.id)
                .await?;
            stats.events_exploded += 1;
        }
        Ok(())
    }

    /// The deliver stage: claim due deliveries and attempt each. On a 2xx the delivery is
    /// marked delivered; on a failure it is scheduled for a bounded backoff retry, or
    /// dead-lettered once the attempts cap is reached. Each delivery is independent, so a
    /// slow or failing RP never blocks another.
    async fn deliver(
        &self,
        scope: Scope,
        stats: &mut DrainStats,
    ) -> Result<(), ironauth_store::StoreError> {
        let scoped = self.store.scoped(scope);
        let due = scoped
            .backchannel_deliveries()
            .claim_due(&self.env, self.settings.lease, self.settings.batch)
            .await?;
        for delivery in &due {
            let outcome = self.attempt_one(scope, delivery).await;
            let deliveries = scoped.backchannel_deliveries();
            match outcome {
                Ok(()) => {
                    deliveries.mark_delivered(&self.env, &delivery.id).await?;
                    stats.delivered += 1;
                }
                Err(failure) => {
                    // This claim was one attempt; count it and decide.
                    let attempts_after = delivery.attempts.saturating_add(1);
                    let cap = i32::try_from(self.settings.max_attempts).unwrap_or(i32::MAX);
                    if attempts_after >= cap {
                        deliveries
                            .record_failure(
                                &self.env,
                                &delivery.id,
                                attempts_after,
                                None,
                                &failure.label(),
                            )
                            .await?;
                        stats.dead_lettered += 1;
                    } else {
                        let next = self.next_attempt_micros(attempts_after);
                        deliveries
                            .record_failure(
                                &self.env,
                                &delivery.id,
                                attempts_after,
                                Some(next),
                                &failure.label(),
                            )
                            .await?;
                        stats.retried += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// Attempt ONE delivery: build the RP's own signed Logout Token, then POST it through
    /// the sender. A missing signing key (an unprovisioned environment) is a
    /// [`SendFailure::Transport`], so the delivery is retried and eventually dead-lettered
    /// rather than lost.
    async fn attempt_one(
        &self,
        scope: Scope,
        delivery: &ironauth_store::LogoutDelivery,
    ) -> Result<(), SendFailure> {
        let token = self
            .build_token(scope, &delivery.client_id, &delivery.sid, &delivery.jti)
            .await?;
        self.sender.deliver(&delivery.logout_uri, &token).await
    }

    /// Build and sign the Logout Token for one (client, session) pair, through the SAME
    /// per-environment issuer/key and ironauth-jose core an ID token uses. The `jti` is
    /// the delivery's OWN, minted once at explode time and reused across every attempt, so
    /// a retry re-POSTs the SAME token and the RP dedups on it.
    async fn build_token(
        &self,
        scope: Scope,
        client_id: &str,
        sid: &str,
        jti: &str,
    ) -> Result<String, SendFailure> {
        let now = self.env.clock().now_utc();
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
            &EmissionOptions::new().with_typ(LOGOUT_TOKEN_TYP),
        )
        .map_err(|_| SendFailure::Transport)
    }

    /// The instant (epoch micros) the next retry becomes due: `now + base * 2^(n-1)`
    /// seconds plus a jitter of up to `base` seconds, both drawn from the deterministic
    /// clock and entropy seams (so the schedule is exact under a manual clock in tests).
    /// The exponential term is capped to avoid an absurd or overflowing delay.
    fn next_attempt_micros(&self, attempt_after: i32) -> i64 {
        let now = self.env.clock().now_utc();
        let base = self.settings.retry_base.as_secs().max(1);
        let shift = u32::try_from(attempt_after.saturating_sub(1))
            .unwrap_or(0)
            .min(16);
        let backoff = base.saturating_mul(1_u64 << shift).min(MAX_BACKOFF_SECS);
        let mut bytes = [0_u8; 8];
        self.env.entropy().fill_bytes(&mut bytes);
        let jitter = u64::from_le_bytes(bytes) % base;
        let total = backoff.saturating_add(jitter).min(MAX_BACKOFF_SECS);
        let delta_micros = i64::try_from(total)
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000_000);
        unix_micros(now).saturating_add(delta_micros)
    }
}

/// Seconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Microseconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
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
