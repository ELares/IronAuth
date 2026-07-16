// SPDX-License-Identifier: MIT OR Apache-2.0

//! Step-up authentication policy: the declarative authentication requirement and
//! its evaluation against a recorded authentication (RFC 9470, issue #72).
//!
//! A [`AuthnRequirement`] is an `(acr floor, max auth age)` pair. It is assembled
//! from three declarative sources at three evaluation points:
//!
//! - the request's `acr_values` and `max_age` (OIDC Core 3.1.2.1, RFC 9470),
//! - the per-client registration floor (`clients.step_up_acr` /
//!   `clients.step_up_max_age_secs`), and
//! - the per-scope tenant policy (`scope_step_up_policies`), keyed by the OAuth
//!   scope tokens a request asks for.
//!
//! The requirement is evaluated at authorization (does the current session meet
//! it, or must a factor run?), at token issuance (does the frozen authentication on
//! the code meet it?), and on refresh (has the auth-age window lapsed, forcing a
//! new step-up?). Every evaluation compares the requirement against the ACHIEVED
//! `acr` and the recorded `auth_time` derived from what ACTUALLY happened (issue
//! #14), never an asserted request value; a stepped-up token therefore always
//! carries an `acr`/`auth_time` that reflect the real authentication.
//!
//! # ACR ordering
//!
//! `acr` values are compared by their position in the DEPLOYMENT-configured order
//! (weakest first), which defaults to the credential-ladder order the registry
//! advertises (`pwd` < `mfa` < `phr` < `phrh`, see [`crate::authn`]). The order is
//! resolved once from `oidc.acr_order` (per-(tenant, environment) resolution is a
//! future enhancement). A floor is
//! satisfied when the achieved `acr` is the SAME value or ranks at least as strong.
//! An `acr` absent from the order can only be satisfied by an exact match, so an
//! unknown floor never silently passes.

use crate::authn;

/// The default `acr` order (weakest to strongest): the credential-ladder order the
/// registry advertises. A deployment may override it through `oidc.acr_order`.
#[must_use]
pub fn default_acr_order() -> Vec<String> {
    authn::acr_values_supported()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// Canonicalize an operator-supplied `acr` alias to the value the enforcement path
/// compares against (issue #72). A short alias (`pwd`, `mfa`, `phr`, `phrh`) maps to the
/// server's canonical `acr` for that level (for example `mfa` -> `urn:ironauth:acr:mfa`),
/// so a policy set through the CLI with `--acr mfa` is stored in the same form the
/// achieved `acr` carries and actually gates. Any value that is already a full canonical
/// `acr`, or an unrecognized custom value, passes through verbatim (an unranked custom
/// floor still only ever matches exactly, per [`acr_satisfies`]).
#[must_use]
pub fn canonical_step_up_acr(alias: &str) -> String {
    for acr in authn::acr_values_supported() {
        // An exact canonical value passes through; a bare level alias matches the last
        // `:`-delimited segment of the canonical acr (so `mfa` maps to `...:mfa`).
        if acr == alias || acr.rsplit(':').next() == Some(alias) {
            return acr.to_owned();
        }
    }
    alias.to_owned()
}

/// The rank of an `acr` in `order` (weakest is 0), or [`None`] when the value is
/// not in the configured order.
#[must_use]
pub fn acr_rank(acr: &str, order: &[String]) -> Option<usize> {
    order.iter().position(|candidate| candidate == acr)
}

/// Whether an `achieved` `acr` satisfies a `required` floor under `order`.
///
/// The same value always satisfies itself. Otherwise both must be ranked and the
/// achieved rank must be at least the required rank. A floor not present in the
/// order can only be met by an exact match, so an unknown or misconfigured floor
/// fails closed rather than passing on a partial comparison.
#[must_use]
pub fn acr_satisfies(achieved: &str, required: &str, order: &[String]) -> bool {
    if achieved == required {
        return true;
    }
    match (acr_rank(achieved, order), acr_rank(required, order)) {
        (Some(achieved_rank), Some(required_rank)) => achieved_rank >= required_rank,
        _ => false,
    }
}

/// A declarative authentication requirement: an optional `acr` floor and an
/// optional maximum authentication age (seconds).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthnRequirement {
    /// The minimum `acr` the authentication must achieve, if any.
    pub min_acr: Option<String>,
    /// The maximum age of the authentication in seconds, if any (a `max_age`
    /// window). An authentication older than this must be repeated.
    pub max_auth_age_secs: Option<u64>,
}

impl AuthnRequirement {
    /// Whether this requirement constrains anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.min_acr.is_none() && self.max_auth_age_secs.is_none()
    }

    /// Fold `other` into `self`, keeping the STRONGER constraint of each dimension:
    /// the higher-ranked `acr` floor (under `order`) and the SMALLER maximum age.
    /// This is the "must satisfy all sources" semantics: the request, the client
    /// floor, and every requested scope's policy all apply at once.
    pub fn merge_stronger(&mut self, other: &AuthnRequirement, order: &[String]) {
        if let Some(candidate) = &other.min_acr {
            self.min_acr = Some(match self.min_acr.take() {
                Some(current) => stronger_acr(current, candidate.clone(), order),
                None => candidate.clone(),
            });
        }
        if let Some(candidate) = other.max_auth_age_secs {
            self.max_auth_age_secs = Some(match self.max_auth_age_secs {
                Some(current) => current.min(candidate),
                None => candidate,
            });
        }
    }
}

/// The stronger (higher-ranked) of two `acr` values under `order`. An unranked
/// value is treated as weaker than any ranked one (a misconfigured floor never
/// silently outranks a known one); between two unranked values the first is kept.
fn stronger_acr(left: String, right: String, order: &[String]) -> String {
    match (acr_rank(&left, order), acr_rank(&right, order)) {
        (Some(l), Some(r)) if r > l => right,
        (None, Some(_)) => right,
        _ => left,
    }
}

/// The requirement expressed by a request's `acr_values` (a space-separated,
/// preference-ordered list) under `order`.
///
/// For step-up the floor is the STRONGEST listed value (highest rank): reaching it
/// satisfies every weaker alternative the client listed, and it is the secure
/// reading of a client that asks for elevated assurance. An empty or whitespace
/// list yields no floor. `max_age` is carried separately (it is not part of
/// `acr_values`).
#[must_use]
pub fn requirement_from_acr_values(
    acr_values: Option<&str>,
    max_age_secs: Option<u64>,
    order: &[String],
) -> AuthnRequirement {
    let min_acr = acr_values
        .map(str::split_whitespace)
        .into_iter()
        .flatten()
        .fold(None::<String>, |acc, value| match acc {
            Some(current) => Some(stronger_acr(current, value.to_owned(), order)),
            None => Some(value.to_owned()),
        });
    AuthnRequirement {
        min_acr,
        max_auth_age_secs: max_age_secs,
    }
}

/// The outcome of evaluating a requirement against a recorded authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Satisfaction {
    /// The recorded authentication meets the requirement.
    Satisfied,
    /// The requirement is not met and a step-up is needed. The flags record WHY,
    /// so a caller can pick the right remediation (a factor step-up for an unmet
    /// `acr`, a full re-authentication for a lapsed age window).
    NeedsStepUp {
        /// The achieved `acr` does not satisfy the floor.
        acr_unmet: bool,
        /// The authentication is older than the allowed window (or its age cannot
        /// be established, which fails closed).
        age_lapsed: bool,
    },
}

/// Whether an authentication recorded at `auth_time_micros` is older than a
/// `max_age` window at `now_micros`. A missing `auth_time` when an age bound
/// applies FAILS CLOSED (the freshness cannot be proven, so the window is treated
/// as lapsed): the acceptance-critical rule that a refresh can never silently
/// extend a stale window. A future-dated `auth_time` (a frozen test clock) is never
/// stale.
#[must_use]
fn age_lapsed(max_age_secs: u64, auth_time_micros: Option<i64>, now_micros: i64) -> bool {
    let Some(auth_time) = auth_time_micros else {
        return true;
    };
    let elapsed = now_micros.saturating_sub(auth_time);
    let window = i64::try_from(max_age_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    elapsed > window
}

/// Evaluate a requirement against a recorded authentication: the `achieved_acr`
/// (derived from the recorded methods, issue #14), the recorded `auth_time`, and
/// the clock instant `now_micros`, under the tenant `order`.
#[must_use]
pub fn evaluate(
    requirement: &AuthnRequirement,
    achieved_acr: &str,
    auth_time_micros: Option<i64>,
    now_micros: i64,
    order: &[String],
) -> Satisfaction {
    let acr_unmet = requirement
        .min_acr
        .as_deref()
        .is_some_and(|floor| !acr_satisfies(achieved_acr, floor, order));
    let age_lapsed = requirement
        .max_auth_age_secs
        .is_some_and(|secs| age_lapsed(secs, auth_time_micros, now_micros));
    if acr_unmet || age_lapsed {
        Satisfaction::NeedsStepUp {
            acr_unmet,
            age_lapsed,
        }
    } else {
        Satisfaction::Satisfied
    }
}

/// Whether a set of authentication methods can, IN PRINCIPLE, achieve the `acr`
/// floor: some `acr` the server can achieve ranks at least as strong as the floor.
/// Used to distinguish "the user must step up (a qualifying factor exists)" from
/// "no method can ever satisfy this" (the `unmet_authentication_requirements`
/// failure).
#[must_use]
pub fn floor_is_achievable(floor: &str, order: &[String]) -> bool {
    authn::acr_values_supported()
        .into_iter()
        .any(|supported| acr_satisfies(supported, floor, order))
}

use ironauth_store::{ClientRecord, Scope, UserId};

use crate::state::OidcState;

/// Assemble the effective authentication requirement for a request from the three
/// declarative sources (issue #72): the request `acr_values` / `max_age`, the
/// per-client floor, and the per-scope tenant policy for each requested OAuth scope.
/// The strongest constraint of each dimension wins (the highest `acr` floor and the
/// smallest age window), so a request must satisfy every source at once.
///
/// Returns the assembled requirement AND a `policy_read_faulted` flag: `true` when the
/// per-scope policy read hit a store fault, so the requirement may be INCOMPLETE (a
/// governing policy could exist but was not seen). The authorization endpoint (the
/// primary gate) treats a fault as best-effort and ignores it; the token/refresh path
/// FAILS CLOSED on it (issue #72 INFO), so a store blip can never silently skip a policy
/// added after the code or family was issued.
pub(crate) async fn requirement_for_request(
    state: &OidcState,
    scope: Scope,
    client: &ClientRecord,
    requested_scope: Option<&str>,
    acr_values: Option<&str>,
    max_age_secs: Option<u64>,
) -> (AuthnRequirement, bool) {
    let order = state.acr_order();
    // The request `acr_values` is a VOLUNTARY preference (OIDC Core 3.1.2.1): an
    // UNACHIEVABLE requested value (no method can ever reach it) is best-effort and
    // never triggers a step-up or an error (the achieved acr is reflected honestly,
    // issue #14). An ACHIEVABLE requested value (for example the multi-factor acr) is
    // honored as a step-up trigger (RFC 9470). Filtering here keeps the voluntary
    // semantics while an ESSENTIAL acr from the `claims` parameter, folded in by the
    // caller, stays BINDING.
    let achievable_acr_values = acr_values.map(|values| {
        values
            .split_whitespace()
            .filter(|value| floor_is_achievable(value, &order))
            .collect::<Vec<_>>()
            .join(" ")
    });
    let mut requirement =
        requirement_from_acr_values(achievable_acr_values.as_deref(), max_age_secs, &order);
    // The per-client registration floor.
    requirement.merge_stronger(
        &AuthnRequirement {
            min_acr: client.step_up_acr.clone(),
            max_auth_age_secs: client
                .step_up_max_age_secs
                .and_then(|secs| u64::try_from(secs).ok()),
        },
        &order,
    );
    // The per-scope tenant policy for each requested OAuth scope token. A store fault
    // here is SURFACED (not swallowed) so the token/refresh path can fail closed.
    let mut policy_read_faulted = false;
    if let Some(requested) = requested_scope {
        match state
            .store()
            .scoped(scope)
            .scope_step_up_policies()
            .list()
            .await
        {
            Ok(policies) => {
                let requested_tokens: Vec<&str> = requested.split_whitespace().collect();
                for policy in &policies {
                    if requested_tokens.contains(&policy.scope_token.as_str()) {
                        requirement.merge_stronger(
                            &AuthnRequirement {
                                min_acr: policy.min_acr.clone(),
                                max_auth_age_secs: policy
                                    .max_auth_age_secs
                                    .and_then(|secs| u64::try_from(secs).ok()),
                            },
                            &order,
                        );
                    }
                }
            }
            Err(_) => policy_read_faulted = true,
        }
    }
    (requirement, policy_read_faulted)
}

/// How the authorization endpoint should remediate an unmet requirement (issue #72).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Remediation {
    /// Run a FULL re-authentication (redirect to the generic login). Chosen only when
    /// the age window lapsed (the whole session is stale but the achieved `acr` still
    /// meets the floor, so a plain re-login refreshes `auth_time` and terminates).
    FullReauth,
    /// Challenge a SECOND FACTOR against the current session (redirect to the
    /// step-up challenge). Chosen when the floor is at the multi-factor level and the
    /// subject has an enrolled TOTP authenticator.
    SecondFactor,
    /// Run the PASSKEY ceremony SPECIFICALLY (redirect to the passkey-only sign-in),
    /// not the generic login. Chosen when reaching the floor requires a phishing-resistant
    /// factor (a `phr`/`phrh` floor), or an `mfa`-level floor the subject can only reach
    /// with a passkey. A generic re-login would loop forever (a password yields `pwd`,
    /// which never satisfies these floors); the passkey ceremony yields `phr`, which
    /// does, so the flow TERMINATES deterministically.
    PasskeyReauth,
    /// The subject has no qualifying factor but tenant policy allows enrollment:
    /// surface the enrollment prompt on the challenge page.
    Enroll,
    /// The requirement can never be satisfied (no method reaches the floor, or the
    /// subject cannot reach it and no enrollable factor could): fail per RFC 9470 with a
    /// clear, non-looping error, never an under-qualified token.
    Fail,
}

/// Decide how to remediate an unmet requirement for a subject (issue #72), given the
/// evaluation flags. Only called when [`evaluate`] returned
/// [`Satisfaction::NeedsStepUp`].
pub(crate) async fn decide_remediation(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    requirement: &AuthnRequirement,
    acr_unmet: bool,
    age_lapsed: bool,
) -> Remediation {
    let order = state.acr_order();
    let floor = requirement.min_acr.as_deref();

    // A floor no authentication method can EVER reach is unsatisfiable outright.
    if let Some(floor) = floor {
        if !floor_is_achievable(floor, &order) {
            return Remediation::Fail;
        }
    }

    // Probe the subject's enrolled factors once.
    let has_totp = crate::totp::has_active_totp(state, scope, subject).await;
    let has_passkey = crate::totp::has_passkey(state, scope, subject).await;

    // Whether the floor is at (or below) the multi-factor level, so a TOTP second
    // factor is sufficient to reach it. A stronger floor (phr/phrh) needs a passkey.
    let floor_is_mfa_level =
        floor.is_none_or(|floor| acr_satisfies(authn::acr_for_mfa(), floor, &order));

    if acr_unmet {
        if floor_is_mfa_level {
            // An mfa-level floor is reachable by a TOTP second factor OR a UV passkey.
            // A TOTP the subject already holds is a second-factor challenge against the
            // LIVE session (no password re-entry). Otherwise a passkey holder runs the
            // passkey ceremony SPECIFICALLY (a UV passkey reaches, and exceeds, the mfa
            // floor, so it terminates); a generic re-login is NOT used here because a
            // password yields `pwd` and would loop.
            if has_totp {
                return Remediation::SecondFactor;
            }
            if has_passkey {
                return Remediation::PasskeyReauth;
            }
            // No qualifying factor: enroll one where the tenant offers a factor that can
            // reach the floor (TOTP or a passkey both reach mfa); otherwise it can never
            // be met.
            return if state.totp_enabled() || state.webauthn_enabled() {
                Remediation::Enroll
            } else {
                Remediation::Fail
            };
        }
        // A phr/phrh floor: ONLY a phishing-resistant UV passkey can reach it. A password
        // re-login yields `pwd` and a TOTP yields `mfa`, so NEITHER a generic /login nor a
        // TOTP enrollment can EVER satisfy it -- routing there loops forever (the bug this
        // fixes), and the TOTP `Enroll` prompt is itself a dead-end (enrolling TOTP can
        // never reach phr). A passkey holder is routed to the passkey ceremony SPECIFICALLY
        // (completing it yields `phr`, so it TERMINATES). A subject with NO passkey FAILS
        // CLOSED with a clear, non-looping "a passkey is required" error, never a TOTP
        // dead-end and never an under-qualified token.
        if has_passkey {
            return Remediation::PasskeyReauth;
        }
        return Remediation::Fail;
    }

    // Only the age window lapsed (the acr is met but the authentication is stale):
    // a full re-authentication refreshes auth_time honestly and terminates (the acr
    // already satisfies the floor, so a plain re-login is enough).
    let _ = age_lapsed;
    Remediation::FullReauth
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "urn:ironauth:acr:pwd";
    const MFA: &str = "urn:ironauth:acr:mfa";
    const PHR: &str = "phr";
    const PHRH: &str = "phrh";

    fn order() -> Vec<String> {
        default_acr_order()
    }

    #[test]
    fn default_order_is_the_credential_ladder() {
        assert_eq!(default_acr_order(), vec![PWD, MFA, PHR, PHRH]);
    }

    #[test]
    fn acr_satisfaction_honors_rank() {
        let order = order();
        // mfa satisfies a pwd floor (stronger), pwd does not satisfy an mfa floor.
        assert!(acr_satisfies(MFA, PWD, &order));
        assert!(!acr_satisfies(PWD, MFA, &order));
        // Exact match always satisfies.
        assert!(acr_satisfies(MFA, MFA, &order));
        // phrh (strongest) satisfies every floor.
        assert!(acr_satisfies(PHRH, MFA, &order));
        assert!(acr_satisfies(PHRH, PHR, &order));
    }

    #[test]
    fn acr_ordering_honors_the_tenant_order_not_a_global_one() {
        // A tenant that ranks mfa ABOVE phr (a deployment that trusts its TOTP
        // posture over synced passkeys) changes the comparison: under this order phr
        // no longer satisfies an mfa floor.
        let tenant_order: Vec<String> = [PWD, PHR, MFA, PHRH]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(!acr_satisfies(PHR, MFA, &tenant_order));
        assert!(acr_satisfies(MFA, PHR, &tenant_order));
        // Under the default order the reverse holds.
        assert!(acr_satisfies(PHR, MFA, &order()));
    }

    #[test]
    fn unknown_floor_only_matches_exactly() {
        let order = order();
        assert!(acr_satisfies(
            "urn:custom:acr:x",
            "urn:custom:acr:x",
            &order
        ));
        assert!(!acr_satisfies(PHRH, "urn:custom:acr:x", &order));
    }

    #[test]
    fn requirement_from_acr_values_takes_the_strongest() {
        let order = order();
        let req = requirement_from_acr_values(Some("urn:ironauth:acr:pwd phr"), None, &order);
        assert_eq!(req.min_acr.as_deref(), Some(PHR));
        assert!(requirement_from_acr_values(None, None, &order).is_empty());
        assert!(requirement_from_acr_values(Some("   "), None, &order).is_empty());
    }

    #[test]
    fn merge_keeps_the_stronger_acr_and_the_smaller_age() {
        let order = order();
        let mut req = AuthnRequirement {
            min_acr: Some(MFA.to_owned()),
            max_auth_age_secs: Some(600),
        };
        req.merge_stronger(
            &AuthnRequirement {
                min_acr: Some(PWD.to_owned()),
                max_auth_age_secs: Some(300),
            },
            &order,
        );
        assert_eq!(req.min_acr.as_deref(), Some(MFA), "stronger acr wins");
        assert_eq!(req.max_auth_age_secs, Some(300), "smaller age wins");
        // Merging a stronger acr replaces the floor.
        req.merge_stronger(
            &AuthnRequirement {
                min_acr: Some(PHRH.to_owned()),
                max_auth_age_secs: None,
            },
            &order,
        );
        assert_eq!(req.min_acr.as_deref(), Some(PHRH));
    }

    #[test]
    fn evaluate_flags_acr_and_age() {
        let order = order();
        let now = 2_000_000_000_000_000_i64;
        // mfa floor, achieved pwd: acr unmet.
        let req = AuthnRequirement {
            min_acr: Some(MFA.to_owned()),
            max_auth_age_secs: None,
        };
        assert_eq!(
            evaluate(&req, PWD, Some(now), now, &order),
            Satisfaction::NeedsStepUp {
                acr_unmet: true,
                age_lapsed: false
            }
        );
        // mfa floor, achieved mfa: satisfied.
        assert_eq!(
            evaluate(&req, MFA, Some(now), now, &order),
            Satisfaction::Satisfied
        );
        // age window lapsed even when acr matches.
        let aged = AuthnRequirement {
            min_acr: Some(MFA.to_owned()),
            max_auth_age_secs: Some(300),
        };
        let stale = now - 400 * 1_000_000;
        assert_eq!(
            evaluate(&aged, MFA, Some(stale), now, &order),
            Satisfaction::NeedsStepUp {
                acr_unmet: false,
                age_lapsed: true
            }
        );
        // fresh within window: satisfied.
        let fresh = now - 100 * 1_000_000;
        assert_eq!(
            evaluate(&aged, MFA, Some(fresh), now, &order),
            Satisfaction::Satisfied
        );
    }

    #[test]
    fn missing_auth_time_with_an_age_bound_fails_closed() {
        let order = order();
        let now = 2_000_000_000_000_000_i64;
        let req = AuthnRequirement {
            min_acr: None,
            max_auth_age_secs: Some(300),
        };
        // No recorded auth_time and an age bound: treated as lapsed (fail closed), so
        // a refresh can never silently extend a window it cannot prove is fresh.
        assert_eq!(
            evaluate(&req, MFA, None, now, &order),
            Satisfaction::NeedsStepUp {
                acr_unmet: false,
                age_lapsed: true
            }
        );
    }

    #[test]
    fn floor_achievability_distinguishes_step_up_from_impossible() {
        let order = order();
        // mfa and phrh are achievable (the server offers those methods).
        assert!(floor_is_achievable(MFA, &order));
        assert!(floor_is_achievable(PHRH, &order));
        // A floor no method can reach is not achievable.
        assert!(!floor_is_achievable("urn:custom:acr:impossible", &order));
    }
}
