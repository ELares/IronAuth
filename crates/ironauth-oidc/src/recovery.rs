// SPDX-License-Identifier: MIT OR Apache-2.0

//! Account recovery as a first-class subsystem (issue #81): the recovery-domain logic
//! behind the `/recover` HTTP surface (`recover.rs`).
//!
//! Recovery is the weakest link in authentication: an attacker who cannot beat a
//! passkey files a recovery request, and in most products recovery quietly bypasses or
//! removes the strongest factor with less scrutiny than a normal login. IronAuth models
//! it as a DISTINCT, first-class state machine governed by three pillars:
//!
//! - DELAY as a security feature: a recovery that would REDUCE account security is HELD
//!   for a configured [`RecoverySettings::delay_secs`] window before it can complete,
//!   cancellable throughout.
//! - NOTIFICATION everywhere: initiating recovery notifies EVERY registered channel
//!   immediately, with a cancellation path; completion and factor changes notify again.
//! - THE DOWNGRADE INVARIANT: recovery can NEVER silently remove or bypass a factor
//!   STRONGER than the one used to recover. Removing such a factor requires EITHER a
//!   fresh re-verification of an equal-or-stronger factor OR the configured delay window
//!   with notifications.
//!
//! "Stronger" is NOT a new ordering: it reuses the issue #66 credential-ladder / `acr`
//! strength order that `authn.rs` and `step_up.rs` already enforce. Each factor maps to
//! its `acr` through the SAME [`AuthMethod::acr`] machinery, and the comparison is the
//! SAME [`step_up::acr_satisfies`] the step-up gate uses. There is one strength order in
//! the system, and this subsystem consumes it.
//!
//! Risk integration is a SEAM: recovery attempts are risk-scored events through the
//! [`RiskEvaluator`] trait (a null/allow default), so issue #79's risk engine can force
//! the delay path or block a recovery without this subsystem taking a hard dependency on
//! it.

use ironauth_store::{
    CorrelationId, IdentifierType, NewRecoveryFlow, RecoveryCancelReason, RecoveryEntryPoint,
    RecoveryFlowId, Scope, UserId,
};
use sha2::{Digest, Sha256};

use crate::authn::{self, AuthMethod};
use crate::interaction;
use crate::state::OidcState;
use crate::step_up;
use crate::util::epoch_micros;
use crate::verification::VerificationPurpose;

/// The wire prefix of a recovery cancellation token, mirroring the other `ira_*`
/// reference tokens. The token embeds the `rcv_` flow id (which self-declares its
/// scope) so the cancellation handler resolves the scope from the token alone.
const CANCEL_TOKEN_PREFIX: &str = "ira_rcv_";
/// The delimiter between the flow-id handle and the high-entropy secret.
const CANCEL_TOKEN_DELIMITER: char = '~';
/// The CSPRNG secret length (256 bits) in a cancellation token.
const CANCEL_SECRET_BYTES: usize = 32;

/// The resolved per-environment recovery windows (issue #81): the per-account cooldown
/// between initiations and the delay a security-reducing recovery is held for. Both come
/// from `oidc.recovery_cooldown_secs` / `oidc.recovery_delay_secs`, seeded once on the
/// state so a test drives them under a manual clock.
#[derive(Debug, Clone, Copy)]
pub struct RecoverySettings {
    /// The per-account cooldown between two recovery initiations, in seconds.
    pub cooldown_secs: u64,
    /// The delay a security-reducing recovery is held for, in seconds.
    pub delay_secs: u64,
}

/// An enrolled factor whose removal the downgrade invariant protects, OR the factor a
/// recovery was performed with (issue #81), mapped to the ONE credential-ladder strength
/// (issue #66) via [`AuthMethod::acr`]. This is deliberately NOT a parallel ordering: it
/// is a thin projection onto the existing [`AuthMethod`] table so "stronger" is defined
/// by the same machinery the login/step-up paths use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFactor {
    /// A password (a knowledge factor). `pwd`-level.
    Password,
    /// An email one-time proof (issue #68). `pwd`-level (a single primary factor).
    EmailOtp,
    /// An SMS one-time proof (issue #70). `pwd`-level (the weakest primary factor).
    SmsOtp,
    /// A TOTP authenticator (issue #69). `mfa`-level as a second factor.
    Totp,
    /// A one-time recovery code (issue #69). `mfa`-level (stands in for a second factor).
    RecoveryCode,
    /// A synced (phishing-resistant) passkey. `phr`-level.
    Passkey,
    /// A device-bound (hardware-protected) passkey. `phrh`-level.
    HardwarePasskey,
    /// An attested passkey (issue #66 strongest rung). `attested_passkey`-level.
    AttestedPasskey,
}

impl RecoveryFactor {
    /// The [`AuthMethod`] this factor projects onto. A passkey/recovery/TOTP factor maps
    /// to its user-verified variant, which is the strongest `acr` that credential can
    /// achieve, so the invariant protects it at its full strength.
    #[must_use]
    fn auth_method(self) -> AuthMethod {
        match self {
            RecoveryFactor::Password => AuthMethod::Password,
            RecoveryFactor::EmailOtp => AuthMethod::EmailOtp,
            RecoveryFactor::SmsOtp => AuthMethod::Sms,
            RecoveryFactor::Totp => AuthMethod::Totp,
            RecoveryFactor::RecoveryCode => AuthMethod::RecoveryCode,
            RecoveryFactor::Passkey => AuthMethod::PasskeyVerified,
            RecoveryFactor::HardwarePasskey => AuthMethod::PasskeyHardwareVerified,
            RecoveryFactor::AttestedPasskey => AuthMethod::AttestedPasskeyVerified,
        }
    }

    /// The credential-ladder `acr` strength of this factor (issue #66): the SINGLE
    /// source of "stronger", reused from [`AuthMethod::acr`].
    #[must_use]
    pub fn strength_acr(self) -> &'static str {
        self.auth_method().acr()
    }
}

/// The directive a risk evaluation returns for a recovery attempt (issue #81 / #79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskDirective {
    /// Proceed on the normal path (the recovery is held only if it would reduce
    /// security).
    Allow,
    /// Force the DELAY path even for a recovery that would not otherwise be held, so a
    /// risky-but-not-downgrading recovery still gets the notified, cancellable window.
    ForceDelay,
    /// Block the recovery outright: no flow is created and no notification is sent, but
    /// the caller still returns the uniform acknowledgment (anti-enumeration).
    Block,
}

/// A risk-scored recovery event (issue #81), the input to a [`RiskEvaluator`].
#[derive(Debug)]
pub struct RiskEvent<'a> {
    /// The (tenant, environment) scope the recovery targets.
    pub scope: Scope,
    /// The subject the recovery targets.
    pub subject: &'a UserId,
    /// The entry point the recovery started from.
    pub entry_point: RecoveryEntryPoint,
    /// The `acr` strength of the factor the recovery was performed with.
    pub recover_acr: &'a str,
    /// The resolved peer IP, when available.
    pub client_ip: Option<&'a str>,
}

/// The risk-scoring SEAM for recovery attempts (issue #81): issue #79's risk engine
/// installs its evaluator here to force the delay path or block a recovery per the
/// action vocabulary, WITHOUT this subsystem taking a hard dependency on it. The default
/// [`NullRiskEvaluator`] allows every recovery, so an un-wired deployment behaves exactly
/// as before.
pub trait RiskEvaluator: Send + Sync + std::fmt::Debug {
    /// Score a recovery attempt and return how it must proceed.
    fn evaluate_recovery(&self, event: &RiskEvent<'_>) -> RiskDirective;
}

/// The default recovery risk evaluator (issue #81): allow every recovery. The issue #79
/// risk engine replaces it through [`OidcState::with_risk_evaluator`].
#[derive(Debug, Clone, Copy)]
pub struct NullRiskEvaluator;

impl RiskEvaluator for NullRiskEvaluator {
    fn evaluate_recovery(&self, _event: &RiskEvent<'_>) -> RiskDirective {
        RiskDirective::Allow
    }
}

/// The decision a factor change gets under the downgrade invariant (issue #81).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorChangeDecision {
    /// Not a downgrade: the factor used to recover is equal-or-stronger than the target
    /// factor, so removing or replacing it is allowed outright.
    NotADowngrade,
    /// A downgrade allowed because a FRESH equal-or-stronger factor was re-verified.
    AllowedByReverify,
    /// A downgrade allowed because the configured DELAY window elapsed (with the
    /// notifications sent throughout).
    AllowedByDelay,
    /// A downgrade BLOCKED: it needs the delay window to elapse OR a fresh
    /// equal-or-stronger re-verification. This is the acceptance-critical crux: an
    /// email-OTP recovery can NEVER remove a passkey while this is the decision.
    Blocked,
}

impl FactorChangeDecision {
    /// Whether the factor change may proceed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        !matches!(self, FactorChangeDecision::Blocked)
    }

    /// The stable wire tag for the audit detail.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FactorChangeDecision::NotADowngrade => "not_a_downgrade",
            FactorChangeDecision::AllowedByReverify => "allowed_reverify",
            FactorChangeDecision::AllowedByDelay => "allowed_delay",
            FactorChangeDecision::Blocked => "blocked",
        }
    }
}

/// THE downgrade-invariant decision (issue #81), reusing the issue #66 credential-ladder
/// strength order via [`step_up::acr_satisfies`]. Given the `acr` the recovery was
/// performed with, the `acr` strength of the factor being removed or replaced, an
/// optional fresh re-verification `acr`, and the recovery flow's delay-window horizon,
/// decide whether the change may proceed.
///
/// - If the recovery factor is equal-or-stronger than the target factor, the change is
///   [`FactorChangeDecision::NotADowngrade`] (recovery already proves at least that
///   strength).
/// - Otherwise it is a downgrade, allowed ONLY by a fresh equal-or-stronger
///   re-verification, or by the delay window having elapsed.
/// - Otherwise it is [`FactorChangeDecision::Blocked`].
///
/// A missing `hold_until` (a flow that was never held, so no delay window exists) can
/// never satisfy the delay branch, so a non-delayed flow blocks a downgrade until a
/// re-verification is presented. This fails CLOSED.
#[must_use]
pub fn factor_change_decision(
    recover_acr: &str,
    target_factor_acr: &str,
    reverify_acr: Option<&str>,
    hold_until_unix_micros: Option<i64>,
    now_unix_micros: i64,
    order: &[String],
) -> FactorChangeDecision {
    // Not a downgrade: the factor used to recover ranks at least as strong as the target
    // factor under the ONE credential-ladder order (issue #66).
    if step_up::acr_satisfies(recover_acr, target_factor_acr, order) {
        return FactorChangeDecision::NotADowngrade;
    }
    // A downgrade. A FRESH re-verification of an equal-or-stronger factor satisfies the
    // invariant immediately.
    if let Some(reverify) = reverify_acr {
        if step_up::acr_satisfies(reverify, target_factor_acr, order) {
            return FactorChangeDecision::AllowedByReverify;
        }
    }
    // Otherwise only the elapsed delay window (with its notifications) permits it.
    if let Some(hold_until) = hold_until_unix_micros {
        if now_unix_micros >= hold_until {
            return FactorChangeDecision::AllowedByDelay;
        }
    }
    FactorChangeDecision::Blocked
}

/// The outcome of initiating a recovery (issue #81).
#[derive(Debug)]
pub enum RecoveryInitiation {
    /// A recovery flow was created. `held` marks the delay path (a security-reducing
    /// recovery or a risk-forced delay); `channels_notified` is how many verified
    /// channels were alerted.
    Created {
        /// The new flow's `rcv_` id (the routing handle the links carry).
        flow_id: RecoveryFlowId,
        /// Whether the flow is HELD in the delay window.
        held: bool,
        /// How many verified channels were notified.
        channels_notified: usize,
        /// The high-entropy cancellation token for the notification link (only its
        /// digest is stored). The real M11 transport embeds it in the delivered
        /// "this was not me" link; it is surfaced here so the caller that owns delivery
        /// can carry it.
        cancel_token: String,
    },
    /// Suppressed SILENTLY for anti-enumeration, the per-account cooldown, or a risk
    /// block: no flow, no notification. The caller returns the SAME uniform
    /// acknowledgment, so a suppressed init is indistinguishable from a delivered one.
    Suppressed,
}

/// The SHA-256 digest of a cancellation token (issue #81): server-side state, never the
/// token itself, so a database dump reveals no usable cancellation secret.
#[must_use]
pub fn cancel_token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Mint a cancellation token `ira_rcv_<flow_id>~<secret>` (issue #81): the scope-declaring
/// flow handle plus 256 bits of CSPRNG entropy from the env seam. The token rides the
/// notification link; only its digest is stored.
#[must_use]
fn generate_cancel_token(state: &OidcState, flow_id: &RecoveryFlowId) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; CANCEL_SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    format!(
        "{CANCEL_TOKEN_PREFIX}{flow_id}{CANCEL_TOKEN_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Extract the `rcv_` flow-id handle from a presented cancellation token, so the scope
/// can be resolved from the token alone (the id self-declares its scope). Returns
/// [`None`] for any token that is not the `ira_rcv_<id>~<secret>` shape.
#[must_use]
pub fn flow_id_from_cancel_token(token: &str) -> Option<&str> {
    token
        .strip_prefix(CANCEL_TOKEN_PREFIX)?
        .split(CANCEL_TOKEN_DELIMITER)
        .next()
        .filter(|handle| !handle.is_empty())
}

/// The absolute cancellation link a recovery notification carries (issue #81): the
/// deployment origin plus `/recover/cancel?token=...`. The link is the "this was not me"
/// path that stops an attacker-initiated recovery in its delay window.
#[must_use]
fn cancel_link(state: &OidcState, token: &str) -> String {
    let base = state.self_origin().unwrap_or_default();
    format!(
        "{base}/recover/cancel?token={}",
        crate::util::percent_encode_query(token)
    )
}

/// The account's strongest enrolled factor strength (issue #81), used to decide whether a
/// recovery would REDUCE security. Reuses the issue #66 ladder: a passkey holder is at
/// the `phr` rung, a TOTP holder at `mfa`, otherwise `pwd`. A read fault degrades to the
/// strongest posture (fail closed toward the DELAY path), so a store blip can never skip
/// the hold.
async fn account_strength_acr(state: &OidcState, scope: Scope, subject: &UserId) -> &'static str {
    if crate::totp::has_passkey(state, scope, subject).await {
        AuthMethod::PasskeyVerified.acr()
    } else if crate::totp::has_active_totp(state, scope, subject).await {
        authn::acr_for_mfa()
    } else {
        AuthMethod::Password.acr()
    }
}

/// Notify EVERY verified channel (all verified emails and phone numbers) of a recovery
/// event (issue #81), through the #68 verification seam. Returns how many channels were
/// notified. A channel notification is the coarse alert (never an OTP), so the real M11
/// transport renders it; the send seam records it for tests.
async fn notify_all_channels(state: &OidcState, scope: Scope, subject: &UserId) -> usize {
    let identifiers = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .list_for_user(subject)
        .await
        .unwrap_or_default();
    let mut count = 0;
    for identifier in identifiers {
        if !identifier.verified {
            continue;
        }
        if matches!(
            identifier.identifier_type,
            IdentifierType::Email | IdentifierType::Phone
        ) {
            // The known-recipient path (a verified, resolved channel), so the send goes
            // out; anti-enumeration suppression is decided earlier, at existence lookup.
            state.dispatch_verification(
                scope,
                VerificationPurpose::Recovery,
                &identifier.raw,
                true,
            );
            count += 1;
        }
    }
    count
}

/// INITIATE a recovery for a resolved subject (issue #81): risk-score the event, enforce
/// the per-account cooldown, decide the delay (held) path, mint the cancellation token,
/// notify EVERY verified channel, and persist the flow. Returns
/// [`RecoveryInitiation::Suppressed`] on a risk block or an in-cooldown repeat, so the
/// caller keeps its response uniform.
///
/// Anti-enumeration: this is called ONLY for a resolved (known) account, so an unknown
/// identifier never reaches it; both the known and unknown paths return the same
/// acknowledgment upstream.
pub async fn initiate_recovery(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    entry_point: RecoveryEntryPoint,
    recover_factor: RecoveryFactor,
    recipient: &str,
    client_ip: Option<&str>,
) -> RecoveryInitiation {
    let settings = state.recovery_settings();
    let recover_acr = recover_factor.strength_acr();
    let now_micros = epoch_micros(state.now());

    // Risk-score the attempt through the #79 seam (null/allow by default).
    let directive = state.evaluate_recovery_risk(&RiskEvent {
        scope,
        subject,
        entry_point,
        recover_acr,
        client_ip,
    });
    if directive == RiskDirective::Block {
        return RecoveryInitiation::Suppressed;
    }

    // Per-account COOLDOWN: a repeated initiation inside the window is suppressed
    // (side-effect-only, so a known account stays response-uniform with an unknown one).
    let cooldown_micros = i64::try_from(settings.cooldown_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    let cooldown_cutoff = now_micros.saturating_sub(cooldown_micros);
    match state
        .store()
        .scoped(scope)
        .recovery_flows()
        .initiations_since(subject, cooldown_cutoff)
        .await
    {
        Ok(0) => {}
        // A repeat inside the cooldown window is suppressed (side-effect-only, so a known
        // account stays response-uniform with an unknown one); a read fault fails closed
        // toward suppression too (no new-flow spam on a store blip).
        Ok(_) | Err(_) => return RecoveryInitiation::Suppressed,
    }

    // A recovery would REDUCE security when the recovery factor does not reach the
    // account's strongest factor. That, or a risk-forced delay, holds the flow.
    let account_acr = account_strength_acr(state, scope, subject).await;
    let order = state.acr_order();
    let reduces_security = !step_up::acr_satisfies(recover_acr, account_acr, &order);
    let held = reduces_security || directive == RiskDirective::ForceDelay;
    let hold_until = held.then(|| {
        let delay_micros = i64::try_from(settings.delay_secs)
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000_000);
        now_micros.saturating_add(delay_micros)
    });

    // Mint the flow id and its cancellation token; only the digest is stored.
    let flow_id = RecoveryFlowId::generate(state.env(), &scope);
    let token = generate_cancel_token(state, &flow_id);
    let digest = cancel_token_digest(&token);

    // Notify EVERY verified channel immediately, with the cancellation path. The link is
    // built for the real transport; the coarse send seam records the alert for tests.
    let _link = cancel_link(state, &token);
    let channels_notified = notify_all_channels(state, scope, subject).await;

    let spec = NewRecoveryFlow {
        id: &flow_id,
        subject,
        entry_point,
        recover_acr,
        cancel_token_digest: &digest,
        recipient,
        hold_until_unix_micros: hold_until,
    };
    let issued = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_flows()
        .initiate(state.env(), spec, channels_notified)
        .await;
    match issued {
        Ok(flow_id) => RecoveryInitiation::Created {
            flow_id,
            held,
            channels_notified,
            cancel_token: token,
        },
        Err(_) => RecoveryInitiation::Suppressed,
    }
}

/// CANCEL a recovery from a presented cancellation token (issue #81): resolve the flow by
/// its token digest under the token's own scope, cancel it (revoking the pending
/// recovery), and notify every channel of the cancellation. Returns whether a pending
/// flow was cancelled. A forged, stale, or already-terminal token is the uniform no-op.
pub async fn cancel_from_token(state: &OidcState, token: &str) -> bool {
    let Some(handle) = flow_id_from_cancel_token(token) else {
        return false;
    };
    let Ok(flow_id) = RecoveryFlowId::parse_declared_scope(handle) else {
        return false;
    };
    let scope = flow_id.scope();
    let digest = cancel_token_digest(token);
    let Ok(Some(record)) = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .by_cancel_digest(&digest)
        .await
    else {
        return false;
    };
    if !record.state.is_pending() {
        return false;
    }
    let Ok(subject) = state
        .store()
        .scoped(scope)
        .users()
        .parse_id(&record.subject)
    else {
        return false;
    };
    let cancelled = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_flows()
        .cancel(
            state.env(),
            &record.id,
            RecoveryCancelReason::UserNotification,
        )
        .await
        .unwrap_or(false);
    if cancelled {
        // Completion and cancellation notify AGAIN, so the owner sees the flow closed.
        notify_all_channels(state, scope, &subject).await;
    }
    cancelled
}

/// Evaluate a factor change against an active recovery under THE DOWNGRADE INVARIANT
/// (issue #81), and AUDIT the decision. This is the enforcement entry point a
/// factor-removal / factor-replacement handler calls: given the recovery flow and the
/// factor being changed (plus an optional fresh re-verification strength), it returns
/// whether the change may proceed and records a `recovery.factor_change` audit row either
/// way, so an attacker-initiated downgrade attempt is ALWAYS reconstructable from the log.
///
/// A missing or terminal flow is treated as NO active recovery, so the change is allowed
/// outright (there is no pending recovery to protect against); the invariant only
/// constrains a change made while a recovery is pending or within its delay window. When
/// the change IS an allowed downgrade, every registered channel is notified again.
pub async fn evaluate_factor_change(
    state: &OidcState,
    scope: Scope,
    flow_id: &RecoveryFlowId,
    target_factor: RecoveryFactor,
    reverify_acr: Option<&str>,
) -> FactorChangeDecision {
    let Ok(Some(flow)) = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(flow_id)
        .await
    else {
        return FactorChangeDecision::NotADowngrade;
    };
    if !flow.state.is_pending() {
        return FactorChangeDecision::NotADowngrade;
    }
    let order = state.acr_order();
    let now = epoch_micros(state.now());
    let target_acr = target_factor.strength_acr();
    let decision = factor_change_decision(
        &flow.recover_acr,
        target_acr,
        reverify_acr,
        flow.hold_until_unix_micros,
        now,
        &order,
    );
    let detail = format!("decision={};target_acr={target_acr}", decision.as_str());
    let Ok(subject) = state.store().scoped(scope).users().parse_id(&flow.subject) else {
        return decision;
    };
    let _ = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_flows()
        .record_factor_change(state.env(), flow_id, &detail)
        .await;
    // A factor change actually carried out (an allowed DOWNGRADE) notifies every channel
    // again, so the owner is alerted that a stronger factor was removed under recovery.
    if matches!(
        decision,
        FactorChangeDecision::AllowedByDelay | FactorChangeDecision::AllowedByReverify
    ) {
        notify_all_channels(state, scope, &subject).await;
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::{FactorChangeDecision, RecoveryFactor, factor_change_decision};
    use crate::authn::AuthMethod;
    use crate::step_up::default_acr_order;

    const PWD: &str = "urn:ironauth:acr:pwd";
    const MFA: &str = "urn:ironauth:acr:mfa";
    const PHR: &str = "phr";

    #[test]
    fn factor_strength_reuses_the_66_ladder() {
        // Each recovery factor projects onto the SAME AuthMethod acr the login/step-up
        // paths use (issue #66); there is no parallel ordering.
        assert_eq!(RecoveryFactor::Password.strength_acr(), PWD);
        assert_eq!(RecoveryFactor::EmailOtp.strength_acr(), PWD);
        assert_eq!(RecoveryFactor::SmsOtp.strength_acr(), PWD);
        assert_eq!(RecoveryFactor::Totp.strength_acr(), MFA);
        assert_eq!(RecoveryFactor::RecoveryCode.strength_acr(), MFA);
        assert_eq!(RecoveryFactor::Passkey.strength_acr(), PHR);
        // And the projection agrees with the AuthMethod table directly.
        assert_eq!(
            RecoveryFactor::Passkey.strength_acr(),
            AuthMethod::PasskeyVerified.acr()
        );
        assert_eq!(RecoveryFactor::Totp.strength_acr(), AuthMethod::Totp.acr());
    }

    #[test]
    fn email_recovery_cannot_remove_a_passkey_without_delay_or_reverify() {
        // THE crux: recover via email OTP (pwd), then attempt to remove a passkey (phr).
        // Without a fresh reverify and before the delay elapses, the change is BLOCKED.
        let order = default_acr_order();
        let recover = RecoveryFactor::EmailOtp.strength_acr();
        let target = RecoveryFactor::Passkey.strength_acr();
        let now = 1_000_000_000_i64;
        let hold_until = now + 3_600_000_000; // one hour out (micros).

        // Before the delay elapses, no reverify: BLOCKED.
        assert_eq!(
            factor_change_decision(recover, target, None, Some(hold_until), now, &order),
            FactorChangeDecision::Blocked
        );
        // A weaker reverify (another email OTP, pwd) does NOT unblock it.
        assert_eq!(
            factor_change_decision(recover, target, Some(PWD), Some(hold_until), now, &order),
            FactorChangeDecision::Blocked
        );
        // A fresh EQUAL-or-stronger reverify (a passkey, phr) unblocks it immediately.
        assert_eq!(
            factor_change_decision(recover, target, Some(PHR), Some(hold_until), now, &order),
            FactorChangeDecision::AllowedByReverify
        );
        // After the delay window elapses (clock advanced past hold_until), allowed.
        assert_eq!(
            factor_change_decision(recover, target, None, Some(hold_until), hold_until, &order),
            FactorChangeDecision::AllowedByDelay
        );
    }

    #[test]
    fn recovery_with_an_equal_or_stronger_factor_is_not_a_downgrade() {
        let order = default_acr_order();
        let now = 0_i64;
        // Recover via a passkey (phr), remove a password (pwd): not a downgrade.
        assert_eq!(
            factor_change_decision(PHR, PWD, None, None, now, &order),
            FactorChangeDecision::NotADowngrade
        );
        // Recover via TOTP (mfa), remove a password (pwd): not a downgrade.
        assert_eq!(
            factor_change_decision(MFA, PWD, None, None, now, &order),
            FactorChangeDecision::NotADowngrade
        );
        // Removing an equal-strength factor is not a downgrade (email removes email).
        assert_eq!(
            factor_change_decision(PWD, PWD, None, None, now, &order),
            FactorChangeDecision::NotADowngrade
        );
    }

    #[test]
    fn a_non_held_downgrade_fails_closed_until_reverify() {
        // A flow that was never held (no delay window) can never satisfy the delay
        // branch, so a downgrade stays BLOCKED until a fresh reverify is presented.
        let order = default_acr_order();
        assert_eq!(
            factor_change_decision(PWD, PHR, None, None, i64::MAX, &order),
            FactorChangeDecision::Blocked
        );
    }

    #[test]
    fn the_delay_timer_is_an_exact_clock_comparison() {
        // The delay boundary is a pure clock comparison (no wall-clock sleep): blocked one
        // microsecond before the horizon, allowed exactly at it.
        let order = default_acr_order();
        let recover = RecoveryFactor::EmailOtp.strength_acr();
        let target = RecoveryFactor::Totp.strength_acr();
        let hold_until = 5_000_000_i64;
        assert_eq!(
            factor_change_decision(
                recover,
                target,
                None,
                Some(hold_until),
                hold_until - 1,
                &order
            ),
            FactorChangeDecision::Blocked
        );
        assert_eq!(
            factor_change_decision(recover, target, None, Some(hold_until), hold_until, &order),
            FactorChangeDecision::AllowedByDelay
        );
    }
}
