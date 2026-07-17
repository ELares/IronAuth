// SPDX-License-Identifier: MIT OR Apache-2.0

//! The broker overlay (issue #77 PR 2): the org connection policy IronAuth layers ON TOP
//! of a brokered upstream authentication, regardless of how permissive that upstream is.
//!
//! An org connection carries three nullable overlay columns (shipped by PR 1, consumed
//! here): `overlay_min_acr`, `max_age_secs`, and `overlay_min_class`. This module maps
//! them into the ONE declarative [`AuthnRequirement`] the step-up subsystem (issue #72)
//! already evaluates, so the overlay reuses the SAME acr ladder, the SAME strongest-wins
//! [`AuthnRequirement::merge_stronger`] composition, and the SAME ceremony machinery a
//! client or per-scope floor does. There is deliberately NO new acr/amr path: the overlay
//! only ever RAISES a requirement, and the token's `acr`/`amr` still derive solely from
//! the recorded authentication event (issue #14), so a factor appears in `amr` only when a
//! real ceremony ran.
//!
//! # Where it is enforced
//!
//! The overlay is enforced at the authorization step-up gate ([`crate::authorize`]) via
//! the session subject's STAMPED org connection ([`requirement_for_session_org`]). That
//! gate re-runs on every authorization request and is the SINGLE non-bypassable choke
//! point, so a user cannot skip a federation-callback redirect and reach `/authorize`
//! directly at the unranked federated `acr`. The stamped `org_connection_id` was written
//! by PR 1 FROM the consumed, single-use correlation row (never a browser value), so the
//! overlay source is server-authenticated. The federation callback ALSO composes and
//! evaluates the overlay right after establishing the session, to send the user STRAIGHT
//! to the required ceremony (a better path than bouncing through `/authorize` first).
//!
//! # Honesty
//!
//! The federated context `acr` is deliberately UNRANKED (issue #75): it satisfies only an
//! exact `federated` floor and no local `pwd`/`mfa`/`phr` floor. So an overlay `mfa` (or
//! passkey) floor is NEVER satisfied by the federated login alone and forces a REAL local
//! ceremony; only completing that ceremony records the second factor, so `amr` gains `mfa`
//! honestly, never from the mere fact that an overlay was configured.

use axum::response::Response;
use ironauth_store::{OrgConnectionId, OrgConnectionRecord, Scope, StoreError, UserId};

use crate::authn::{self, CredentialClass};
use crate::interaction::{self, SessionCookies};
use crate::state::OidcState;
use crate::step_up::{self, AuthnRequirement};

/// Map an org connection's overlay policy columns into the declarative authentication
/// requirement the step-up subsystem evaluates (issue #77 PR 2).
///
/// - `overlay_min_acr` is canonicalized (a short alias such as `mfa` becomes the server's
///   canonical acr) and folded as an acr floor.
/// - `overlay_min_class` maps through the ONE credential-class ladder ([`authn::acr_for_class`])
///   and folds as an acr floor; the stronger of it and `overlay_min_acr` wins.
/// - `max_age_secs` folds as a maximum authentication age.
///
/// A `pwd`-level floor (equivalently the `any` credential class) is DROPPED: it is the
/// honest floor and constrains nothing, so it must never force a ceremony on a federated
/// login (whose acr is unranked and would otherwise never satisfy even `pwd`). A NULL /
/// absent overlay therefore yields an EMPTY requirement, so a plain federated login with
/// no overlay configured resumes exactly as before.
#[must_use]
pub(crate) fn overlay_requirement(
    record: &OrgConnectionRecord,
    order: &[String],
) -> AuthnRequirement {
    let mut requirement = AuthnRequirement::default();

    if let Some(acr) = record.overlay_min_acr.as_deref() {
        let canonical = step_up::canonical_step_up_acr(acr);
        requirement.merge_stronger(
            &AuthnRequirement {
                min_acr: Some(canonical),
                max_auth_age_secs: None,
            },
            order,
        );
    }

    if let Some(token) = record.overlay_min_class.as_deref() {
        if let Some(class) = CredentialClass::from_token(token) {
            requirement.merge_stronger(
                &AuthnRequirement {
                    min_acr: Some(authn::acr_for_class(class).to_owned()),
                    max_auth_age_secs: None,
                },
                order,
            );
        }
    }

    if let Some(secs) = record.max_age_secs {
        if let Ok(secs) = u64::try_from(secs) {
            requirement.merge_stronger(
                &AuthnRequirement {
                    min_acr: None,
                    max_auth_age_secs: Some(secs),
                },
                order,
            );
        }
    }

    // A pwd-level floor (the `any` credential class, or an explicit `pwd` acr) is the
    // honest floor and constrains nothing: drop it so an overlay that requires nothing
    // never forces a ceremony on the (unranked) federated context. The max-age bound, if
    // any, is retained.
    if requirement.min_acr.as_deref() == Some(authn::acr_for_class(CredentialClass::Any)) {
        requirement.min_acr = None;
    }

    requirement
}

/// The overlay requirement for a SESSION's subject, resolved from the org connection the
/// subject is STAMPED with (issue #77 PR 2), for the authorization step-up gate.
///
/// Returns an EMPTY requirement when the subject has no org connection or its overlay
/// columns are all NULL (the no-overlay path, unchanged behavior). A store fault reading
/// the stamped org connection or the org connection row is surfaced as `Err(())` so the
/// gate can FAIL CLOSED: an org's overlay must never be silently skipped because a read
/// blipped.
pub(crate) async fn requirement_for_session_org(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    order: &[String],
) -> Result<AuthnRequirement, ()> {
    let scoped = state.store().scoped(scope);
    let ocn_id = match scoped.users().org_connection(subject).await {
        Ok(Some(ocn_id)) => ocn_id,
        // No stamped org connection: no overlay applies. A missing user row (NotFound) is
        // treated as no overlay; the session gate has already resolved the subject.
        Ok(None) | Err(StoreError::NotFound) => return Ok(AuthnRequirement::default()),
        Err(_) => return Err(()),
    };
    requirement_for_org_connection(state, scope, &ocn_id, order).await
}

/// The overlay requirement for a specific `ocn_` org connection (issue #77 PR 2), read
/// from its overlay policy columns. Shared by the session-subject resolver (authorize)
/// and the federation callback (which passes the org connection re-derived from the
/// consumed correlation row). A store fault is `Err(())` (fail closed).
pub(crate) async fn requirement_for_org_connection(
    state: &OidcState,
    scope: Scope,
    ocn_id: &OrgConnectionId,
    order: &[String],
) -> Result<AuthnRequirement, ()> {
    match state
        .store()
        .scoped(scope)
        .org_connections()
        .get(ocn_id)
        .await
    {
        Ok(record) => Ok(overlay_requirement(&record, order)),
        Err(_) => Err(()),
    }
}

/// The federation-callback outcome of the broker overlay (issue #77 PR 2).
pub(crate) enum CallbackOverlay {
    /// No overlay applies (or it is already satisfied): resume the pending request as
    /// usual, exactly as a plain federated login does.
    Resume,
    /// Return this response INSTEAD of resuming: a step-up ceremony redirect that carries
    /// the freshly established session cookies (so the ceremony runs against the federated
    /// session and, on completion, resumes the pending request with the honest combined
    /// factors), or a fail-closed page (with NO session cookies) when the overlay cannot be
    /// satisfied.
    Respond(Response),
}

/// The inputs the federation-callback overlay step needs (issue #77 PR 2).
pub(crate) struct CallbackContext<'a> {
    /// The OIDC application state.
    pub state: &'a OidcState,
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The routed `ocn_` org connection re-derived from the CONSUMED correlation row
    /// (never the browser), or [`None`] for a direct federated login.
    pub org_connection_id: Option<&'a str>,
    /// The validated pending-authorization resume target to send the user back to.
    pub return_to: &'a str,
    /// The provisioned local subject of the federated session.
    pub subject: &'a UserId,
    /// The achieved `acr` of the freshly established federated session (the UNRANKED
    /// federated context for a pure federated login).
    pub achieved_acr: &'a str,
    /// The federated session's recorded `auth_time` in epoch microseconds.
    pub auth_time_micros: i64,
    /// The callback instant in epoch microseconds.
    pub now_micros: i64,
    /// The federated session cookies to carry onto a ceremony redirect.
    pub cookies: &'a SessionCookies,
}

/// Enforce the broker overlay in the federation callback, right after the federated
/// session is established and before the pending request is resumed (issue #77 PR 2).
///
/// Reads the overlay from the org connection re-derived from the CONSUMED correlation row,
/// composes it strongest-wins with the pending request's client and per-scope floor (so
/// the callback routes STRAIGHT to the strongest required ceremony, never a weaker one),
/// and evaluates it against the federated session. On a satisfied (or absent) overlay it
/// resumes. On an unmet overlay it redirects to the EXISTING second-factor or passkey
/// ceremony (carrying the session cookies and the `return_to`), so the user completes a REAL
/// local factor and the resumed request issues a token whose `amr` honestly reflects it. A
/// store fault or an unsatisfiable requirement FAILS CLOSED with no usable session.
///
/// The broker-then-migrate lazy-migration composition (marking this brokered account for a
/// real local-credential cutover) is DEFERRED to a follow-up; it needs a per-account cutover
/// marker and a real cutover trigger that the migration 0059 columns do not carry.
///
/// The authorization step-up gate ([`requirement_for_session_org`]) independently enforces
/// the same overlay on every request, so this callback redirect is the immediate-UX path,
/// not the sole enforcement point (a user cannot bypass the overlay by ignoring it).
pub(crate) async fn enforce_on_callback(ctx: CallbackContext<'_>) -> CallbackOverlay {
    let order = ctx.state.acr_order();
    let Some(raw) = ctx.org_connection_id else {
        // A direct, non-routed federated login: no org binding, so no overlay.
        return CallbackOverlay::Resume;
    };
    let Ok(ocn_id) = OrgConnectionId::parse_in_scope(raw, &ctx.scope) else {
        // The id rode the consumed correlation row; a malformed one is a server-side fault.
        return CallbackOverlay::Respond(interaction::server_error_page());
    };
    let Ok(mut requirement) =
        requirement_for_org_connection(ctx.state, ctx.scope, &ocn_id, &order).await
    else {
        return CallbackOverlay::Respond(interaction::server_error_page());
    };
    if requirement.is_empty() {
        // A NULL / pwd-level overlay: resume exactly as a plain federated login (no prompt,
        // no behavior change).
        return CallbackOverlay::Resume;
    }

    // Compose with the pending request's client and per-scope floor (strongest-wins),
    // reusing the ONE requirement assembler, so the callback never routes to a ceremony
    // WEAKER than the client already requires. Best-effort here (a fault is not fatal): the
    // authorization gate re-composes and re-enforces the client floor on resume.
    if let Some(resume) = interaction::parse_resume(Some(ctx.return_to)) {
        if let Ok(client) = ctx
            .state
            .store()
            .scoped(ctx.scope)
            .clients()
            .get(&resume.client_id)
            .await
        {
            let query = ctx.return_to.split_once('?').map_or("", |(_, q)| q);
            let acr_values = crate::util::query_get(query, "acr_values");
            let max_age = crate::util::query_get(query, "max_age")
                .and_then(|value| value.parse::<u64>().ok());
            let assembled = step_up::requirement_for_request(
                ctx.state,
                ctx.scope,
                &client,
                resume.oauth_scope.as_deref(),
                acr_values.as_deref(),
                max_age,
            )
            .await;
            requirement.merge_stronger(&assembled.requirement, &order);
        }
    }

    let (acr_unmet, age_lapsed) = match step_up::evaluate(
        &requirement,
        ctx.achieved_acr,
        Some(ctx.auth_time_micros),
        ctx.now_micros,
        &order,
    ) {
        step_up::Satisfaction::Satisfied => return CallbackOverlay::Resume,
        step_up::Satisfaction::NeedsStepUp {
            acr_unmet,
            age_lapsed,
        } => (acr_unmet, age_lapsed),
    };

    // The overlay is forcing a local-credential step-up. Composing this with the lazy-migration
    // hook (the broker-then-migrate cutover that would mark THIS brokered account for a real
    // local-credential cutover) is DEFERRED to a follow-up: it needs a per-account cutover
    // marker column plus a real cutover trigger, neither of which the columns migration 0059
    // shipped, so PR 2 deliberately composes NO migration signal here (the hook's global
    // "migrated users" counter means "created locally by a verified first login", which a
    // step-up is not).

    // Remediate with a REAL local ceremony. For a pure age lapse (the acr is met but the
    // authentication is stale) synthesize an `mfa` floor so remediation forces a fresh
    // second factor that refreshes `auth_time` and terminates; a federated `FullReauth`
    // would loop back through `/login` (a password re-entry a federated user has no way to
    // satisfy). Passing `acr_unmet = true` keeps decide_remediation on the factor-challenge
    // branch (never the full-reauth branch).
    let remediation_requirement = if acr_unmet {
        requirement.clone()
    } else {
        AuthnRequirement {
            min_acr: Some(authn::acr_for_mfa().to_owned()),
            max_auth_age_secs: None,
        }
    };
    let remediation = step_up::decide_remediation(
        ctx.state,
        ctx.scope,
        ctx.subject,
        &remediation_requirement,
        true,
        age_lapsed,
    )
    .await;

    let response = match remediation {
        // A second factor against the LIVE federated session (an enrolled TOTP).
        step_up::Remediation::SecondFactor => {
            interaction::mfa_challenge_redirect(ctx.return_to, false)
        }
        // No qualifying factor yet, but enrollment is allowed: surface the enrollment prompt.
        // A `FullReauth` is unreachable here (we force the factor-challenge branch), but map
        // it to the same enrollment ceremony defensively so it can never loop through /login.
        step_up::Remediation::Enroll | step_up::Remediation::FullReauth => {
            interaction::mfa_challenge_redirect(ctx.return_to, true)
        }
        // A phishing-resistant floor: run the passkey ceremony specifically.
        step_up::Remediation::PasskeyReauth => interaction::passkey_reauth_redirect(ctx.return_to),
        // The overlay can never be satisfied by this subject (for example a passkey floor
        // with no passkey and no enrollable factor): FAIL CLOSED with NO session cookies, so
        // the brokered login does not resume at a weaker context.
        step_up::Remediation::Fail => {
            return CallbackOverlay::Respond(interaction::server_error_page());
        }
    };

    // Carry the federated session cookies onto the ceremony redirect so the ceremony runs
    // against this session and, on completion, records the honest combined factors.
    CallbackOverlay::Respond(interaction::attach_session_cookies(response, ctx.cookies))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, TenantId};

    use super::*;
    use crate::step_up::default_acr_order;

    const PWD: &str = "urn:ironauth:acr:pwd";
    const MFA: &str = "urn:ironauth:acr:mfa";
    const PHR: &str = "phr";

    /// A record carrying only the overlay policy columns under test; the rest are inert.
    fn record(
        overlay_min_acr: Option<&str>,
        max_age_secs: Option<i64>,
        overlay_min_class: Option<&str>,
    ) -> OrgConnectionRecord {
        let (env, _clock) = Env::deterministic(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            1,
        );
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        OrgConnectionRecord {
            id: OrgConnectionId::generate(&env, &scope),
            organization_id: "org_x".to_owned(),
            connector_id: "cnr_x".to_owned(),
            overlay_min_acr: overlay_min_acr.map(str::to_owned),
            max_age_secs,
            overlay_min_class: overlay_min_class.map(str::to_owned),
            capture_upstream_tokens: false,
            enabled: true,
            created_at_unix_micros: 0,
            updated_at_unix_micros: 0,
        }
    }

    #[test]
    fn a_null_overlay_is_empty_so_a_plain_federated_login_is_unchanged() {
        let order = default_acr_order();
        assert!(overlay_requirement(&record(None, None, None), &order).is_empty());
    }

    #[test]
    fn an_any_class_or_pwd_acr_overlay_constrains_nothing() {
        // `any` is the honest floor; it must NEVER force a ceremony on the unranked
        // federated context (which cannot satisfy even a pwd floor).
        let order = default_acr_order();
        assert!(overlay_requirement(&record(None, None, Some("any")), &order).is_empty());
        assert!(overlay_requirement(&record(Some("pwd"), None, None), &order).is_empty());
        assert!(overlay_requirement(&record(Some(PWD), None, None), &order).is_empty());
    }

    #[test]
    fn an_mfa_class_overlay_folds_to_the_mfa_floor() {
        let order = default_acr_order();
        let req = overlay_requirement(&record(None, None, Some("mfa")), &order);
        assert_eq!(req.min_acr.as_deref(), Some(MFA));
        assert!(req.max_auth_age_secs.is_none());
        // An alias in overlay_min_acr is canonicalized to the same floor.
        let via_acr = overlay_requirement(&record(Some("mfa"), None, None), &order);
        assert_eq!(via_acr.min_acr.as_deref(), Some(MFA));
    }

    #[test]
    fn a_passkey_class_overlay_folds_to_the_phishing_resistant_floor() {
        let order = default_acr_order();
        let req = overlay_requirement(&record(None, None, Some("passkey")), &order);
        assert_eq!(req.min_acr.as_deref(), Some(PHR));
    }

    #[test]
    fn the_stronger_of_acr_and_class_wins() {
        // overlay_min_acr=mfa and overlay_min_class=passkey -> the stronger (passkey/phr).
        let order = default_acr_order();
        let req = overlay_requirement(&record(Some("mfa"), None, Some("passkey")), &order);
        assert_eq!(req.min_acr.as_deref(), Some(PHR));
    }

    #[test]
    fn max_age_folds_as_an_age_bound_and_composes_with_a_floor() {
        let order = default_acr_order();
        let req = overlay_requirement(&record(None, Some(300), Some("mfa")), &order);
        assert_eq!(req.min_acr.as_deref(), Some(MFA));
        assert_eq!(req.max_auth_age_secs, Some(300));
        // A pure max-age overlay is a real requirement even with no acr floor.
        let age_only = overlay_requirement(&record(None, Some(300), None), &order);
        assert!(!age_only.is_empty());
        assert!(age_only.min_acr.is_none());
        assert_eq!(age_only.max_auth_age_secs, Some(300));
    }

    #[test]
    fn strongest_wins_never_downgrades_a_stronger_client_floor() {
        // The acceptance composition: a client requiring passkey (phr) plus an overlay
        // requiring only mfa yields the STRONGER (passkey) effective requirement, so the
        // overlay never weakens the client floor.
        let order = default_acr_order();
        let overlay = overlay_requirement(&record(None, None, Some("mfa")), &order);
        assert_eq!(overlay.min_acr.as_deref(), Some(MFA));
        let mut effective = AuthnRequirement {
            min_acr: Some(PHR.to_owned()),
            max_auth_age_secs: None,
        };
        effective.merge_stronger(&overlay, &order);
        assert_eq!(
            effective.min_acr.as_deref(),
            Some(PHR),
            "the stronger client passkey floor survives the weaker overlay"
        );
        // And the reverse fold (overlay first) is identical (strongest-wins is symmetric).
        let mut reverse = overlay.clone();
        reverse.merge_stronger(
            &AuthnRequirement {
                min_acr: Some(PHR.to_owned()),
                max_auth_age_secs: None,
            },
            &order,
        );
        assert_eq!(reverse.min_acr.as_deref(), Some(PHR));
    }

    #[test]
    fn an_mfa_overlay_forces_a_step_up_against_the_unranked_federated_context() {
        // The heart of the broker overlay: the federated acr is unranked, so an mfa floor
        // is UNMET by a pure federated login, forcing a real local ceremony.
        let order = default_acr_order();
        let req = overlay_requirement(&record(None, None, Some("mfa")), &order);
        let federated = authn::acr_federated();
        let now = 2_000_000_000_000_000_i64;
        assert_eq!(
            step_up::evaluate(&req, federated, Some(now), now, &order),
            step_up::Satisfaction::NeedsStepUp {
                acr_unmet: true,
                age_lapsed: false
            },
            "an mfa overlay is unmet by the unranked federated context"
        );
        // A completed local mfa ceremony (achieved acr mfa) satisfies it.
        assert_eq!(
            step_up::evaluate(&req, MFA, Some(now), now, &order),
            step_up::Satisfaction::Satisfied
        );
    }

    #[test]
    fn a_stale_federated_auth_time_lapses_a_max_age_overlay() {
        let order = default_acr_order();
        let req = overlay_requirement(&record(None, Some(300), None), &order);
        let now = 2_000_000_000_000_000_i64;
        let stale = now - 400 * 1_000_000;
        assert_eq!(
            step_up::evaluate(&req, authn::acr_federated(), Some(stale), now, &order),
            step_up::Satisfaction::NeedsStepUp {
                acr_unmet: false,
                age_lapsed: true
            }
        );
    }
}
