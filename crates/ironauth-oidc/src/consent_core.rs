// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PURE consent-decision core (issue #365).
//!
//! `resolve_consent_gate` (the browser `/authorize` gate) and, in a later PR, the
//! first-party challenge endpoint both make the SAME security-critical consent
//! decision: the consent-lockdown block, the quarantine carve-out disablement, the
//! sensitive-scope strip, the third-party admin gate, the first-party carve-out, and
//! the recorded-consent fast path. Historically each surface hand-mirrored that
//! decision, which is how the challenge mint path once diverged from the gate's
//! quarantine checks. This module is the SINGLE source of truth for the ordered
//! decision, so no surface can drift from it again.
//!
//! The core is PURE and SYNCHRONOUS: it owns NO state, store, clock, or IO. Every
//! value it needs is precomputed by the caller and supplied on [`ConsentInputs`]
//! (the flag-gated quarantine read, the admin-gate read, the recorded-consent
//! handle, the injected `now_micros` determinism seam). The caller performs the IO
//! dictated by the returned [`ConsentDecision`] (record or audit a skipped consent,
//! bind the scope, render the consent screen, or emit the negotiated-mode error), so
//! the observable behavior of each surface is unchanged.
//!
//! The order of the decision IS the security property and is preserved verbatim from
//! `resolve_consent_gate`: lockdown, then the quarantine-aware `force_consent` and
//! carve-out eligibility, then the admin gate, then the first-party carve-out, then
//! the recorded-consent fast path, then the consent-required surface.

use ironauth_config::QuarantineConfig;
use ironauth_store::GrantedConsent;

use crate::authorize::{
    AdminConsentOutcome, consent_covers_scope, consent_expired, strip_sensitive_scopes,
};
use crate::error::AuthzErrorCode;

/// The precomputed inputs to the consent decision (issue #365). The caller does
/// every read (the flag-gated quarantine read, the admin-gate read, the
/// recorded-consent lookup) and supplies the results here; the core reads no store
/// and no clock.
///
/// The many booleans are the precomputed predicates the ordered decision reads (each
/// resolved once by the caller from a distinct source); they are independent inputs,
/// not a state machine, so folding them into two-variant enums would only obscure
/// what each names.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ConsentInputs<'a> {
    /// Whether the CLIENT is quarantined (issue #31): an unverified client is always
    /// re-prompted (it never gets the carve-out or the recorded-consent fast path)
    /// until an admin verifies it.
    pub client_quarantined: bool,
    /// Whether the authenticated USER is quarantined (issue #82). The caller did the
    /// flag-gated `user_is_quarantined` read and failed closed on a store fault; the
    /// core consumes the resolved boolean. A quarantined user never gets the silent
    /// carve-out, and every sensitive scope is stripped from `bound_scope`.
    pub user_quarantined: bool,
    /// Whether `prompt` contains `consent`: a one-shot forced fresh consent screen.
    pub prompt_consent: bool,
    /// Whether `prompt` contains `none`: no UI may be rendered, so an interaction
    /// need becomes the matching negotiated-mode error instead.
    pub prompt_none: bool,
    /// Whether THIS SURFACE trusts the client for the first-party carve-out. The
    /// browser passes `implicit`-mode OR `skip_consent`; the challenge surface passes
    /// `true` (every first-party-only challenge client is carve-out eligible). The
    /// core does NOT re-derive this from `consent_mode`, so each surface keeps its own
    /// eligibility predicate while sharing the security-critical decision.
    pub carveout_trusted: bool,
    /// Whether the client persists a skipped consent (issue #21 no-store knob). When
    /// set, a carve-out records the skipped consent; when clear, it only audits it.
    pub store_skipped_consent: bool,
    /// Whether the consent-lockdown gate BLOCKS this request (issue #88, PR 3): the
    /// caller precomputed `unverified_sensitive_scope_blocked`. Fires FIRST and is
    /// unbypassable.
    pub unverified_sensitive_block: bool,
    /// The third-party admin-consent outcome (issue #88, PR 4). The caller did the
    /// read and failed closed on a fault; a first-party surface passes
    /// [`AdminConsentOutcome::NotApplicable`].
    pub admin: AdminConsentOutcome,
    /// The recorded consent handle for this subject and client, or [`None`] when none
    /// is recorded. The caller did the `granted_ref` read.
    pub recorded: Option<&'a GrantedConsent>,
    /// The request's effective granted scope (issue #21), or [`None`] for the empty
    /// set. The value `bound_scope` is derived from (stripped for a quarantined user).
    pub effective_scope: Option<&'a str>,
    /// The scope set a recorded consent is checked against (issue #21): the caller
    /// applied the `offline_access` consent rule.
    pub consent_check_scope: Option<&'a str>,
    /// The application clock in microseconds since the Unix epoch (the determinism
    /// seam): the caller passes `state.now()`, and the core never reads a clock.
    pub now_micros: i64,
    /// The quarantine denylist used to strip sensitive scopes from a quarantined
    /// user's `bound_scope`.
    pub quarantine_cfg: &'a QuarantineConfig,
}

/// What the caller must do with the grant's consent reference on an auto-grant
/// (issue #365). Each surface performs the same IO the ordered decision has always
/// performed; the core only names WHICH.
pub(crate) enum ConsentRefAction {
    /// Reuse the recorded consent's `con_` id as the grant's consent reference (the
    /// recorded-consent fast path).
    UseRecorded(String),
    /// Record a skipped consent (the store-skipped-consent knob is on) and reference
    /// the new row. The caller records against `bound_scope`.
    RecordSkipped,
    /// Persist NO consent row; only audit the skip with `reason` so the silent
    /// auto-grant still leaves an audit trail. `reason` is the operator-safe detail
    /// naming why consent was skipped (`admin_preauthorized` or `first_party_carveout`).
    AuditOnly { reason: &'static str },
}

/// The consent decision (issue #365): the single outcome the caller acts on.
pub(crate) enum ConsentDecision {
    /// The request is refused. The caller returns the negotiated-mode error built
    /// from `code` and `description` (both preserved verbatim from
    /// `resolve_consent_gate`).
    Denied {
        /// The OAuth error code (`access_denied` for the lockdown and the
        /// admin-approval terminal, `consent_required` under `prompt=none`).
        code: AuthzErrorCode,
        /// The operator-safe error description carried through unchanged.
        description: &'static str,
    },
    /// The request is auto-granted: the caller performs the `consent_ref` IO and
    /// freezes `bound_scope` onto the code.
    AutoGrant {
        /// The scope to bind onto the code: the effective scope, with every sensitive
        /// scope stripped when the USER is quarantined (folding today's step-6a strip
        /// into the single decision). [`None`] for the empty set.
        bound_scope: Option<String>,
        /// The consent-reference IO the caller must perform.
        consent_ref: ConsentRefAction,
    },
    /// A fresh interactive consent is required. The browser renders the consent
    /// screen; the challenge surface (a later PR) escalates to the browser. Only
    /// returned when `prompt` does NOT contain `none` (a `prompt=none` interaction
    /// need is already a [`ConsentDecision::Denied`] `consent_required`).
    NeedsInteractiveConsent,
}

/// Decide the consent outcome for one authorization request (issue #365), PURELY.
///
/// The decision order is the security property and is preserved verbatim from
/// `resolve_consent_gate`:
/// 1. Consent lockdown (issue #88, PR 3): an unverified client requesting a
///    sensitive scope is `access_denied`, ahead of every carve-out, unbypassable.
/// 2. `force_consent = prompt=consent OR the client is quarantined` (issue #31); a
///    quarantined USER (issue #82) is handled by disabling the carve-out and stripping
///    the scope, NOT by folding into `force_consent` (which would trap the account in a
///    consent loop; see `resolve_consent_gate`).
/// 3. First-party carve-out eligibility: trusted by this surface AND neither the client
///    nor the user is quarantined.
/// 4. Third-party admin gate (issue #88, PR 4): a covering pre-authorization skips the
///    user screen unless consent is forced or the user is quarantined; an uncovered
///    third-party request is a terminal `access_denied`.
/// 5. First-party carve-out: auto-grant, recording or auditing the skipped consent.
/// 6. Recorded-consent fast path: a fresh consent covering the checked scope auto-grants
///    unless consent is forced.
/// 7. Consent required: `consent_required` under `prompt=none`, else an interactive
///    consent.
///
/// `bound_scope` folds the step-6a sensitive-scope strip: it is the effective scope with
/// every sensitive scope removed WHEN the user is quarantined, else the effective scope
/// unchanged. It is only meaningful on [`ConsentDecision::AutoGrant`] (a denied or
/// interactive request mints no code).
pub(crate) fn decide(inputs: &ConsentInputs<'_>) -> ConsentDecision {
    // The scope frozen onto any minted code: a quarantined user's sensitive scopes are
    // stripped at this single choke point (issue #82), else the effective scope stands.
    let bound_scope = if inputs.user_quarantined {
        strip_sensitive_scopes(inputs.effective_scope, inputs.quarantine_cfg)
    } else {
        inputs.effective_scope.map(str::to_owned)
    };

    // 1. Consent lockdown (issue #88, PR 3): fires FIRST, ahead of every carve-out and
    //    the recorded-consent fast path, so it is unbypassable.
    if inputs.unverified_sensitive_block {
        return ConsentDecision::Denied {
            code: AuthzErrorCode::AccessDenied,
            description: "an unverified client may not obtain the requested sensitive scope",
        };
    }

    // 2. A quarantined client (issue #31) or an explicit prompt=consent always forces a
    //    fresh screen, which also disables the recorded-consent fast path below. A
    //    quarantined USER is deliberately NOT folded here (it would trap the account in a
    //    consent loop); it disables the carve-out and strips the scope instead.
    let force_consent = inputs.prompt_consent || inputs.client_quarantined;

    // 3. The first-party carve-out applies only to a client this surface trusts, and
    //    never to a quarantined client or user (their trust is ignored, so consent is
    //    always shown until verification clears the quarantine).
    let first_party =
        !inputs.client_quarantined && !inputs.user_quarantined && inputs.carveout_trusted;

    // 4. Third-party admin gate (issue #88, PR 4): a covering pre-authorization is the
    //    consent of record and SKIPS the user screen, but only when consent is not forced
    //    and the user is not quarantined; a forced or quarantined request falls through so
    //    the screen is still shown. An uncovered third-party request is a terminal.
    match inputs.admin {
        AdminConsentOutcome::Covered if !force_consent && !inputs.user_quarantined => {
            return ConsentDecision::AutoGrant {
                bound_scope,
                consent_ref: ConsentRefAction::AuditOnly {
                    reason: "admin_preauthorized",
                },
            };
        }
        AdminConsentOutcome::NotApplicable | AdminConsentOutcome::Covered => {}
        AdminConsentOutcome::RequiresAdminApproval => {
            return ConsentDecision::Denied {
                code: AuthzErrorCode::AccessDenied,
                description: "this application requires administrator approval before it can be authorized",
            };
        }
    }

    // 5. First-party carve-out: auto-grant, recording the skipped consent when the client
    //    stores it, else auditing the skip so it stays enumerable.
    if first_party && !force_consent {
        let consent_ref = if inputs.store_skipped_consent {
            ConsentRefAction::RecordSkipped
        } else {
            ConsentRefAction::AuditOnly {
                reason: "first_party_carveout",
            }
        };
        return ConsentDecision::AutoGrant {
            bound_scope,
            consent_ref,
        };
    }

    // 6. Recorded-consent fast path (issue #21 / #196): a recorded consent authorizes the
    //    request only when it is unexpired AND covers the checked scope as a subset, and
    //    only when consent is not forced.
    let covered = inputs
        .recorded
        .is_some_and(|consent| !consent_expired(consent, inputs.now_micros))
        && consent_covers_scope(inputs.recorded, inputs.consent_check_scope);
    if covered && !force_consent {
        let id = inputs
            .recorded
            .expect("a covering consent is recorded")
            .id
            .clone();
        return ConsentDecision::AutoGrant {
            bound_scope,
            consent_ref: ConsentRefAction::UseRecorded(id),
        };
    }

    // 7. Consent is required: under prompt=none no UI is rendered, so the consent_required
    //    error goes back through the negotiated mode; otherwise a fresh screen is shown.
    if inputs.prompt_none {
        return ConsentDecision::Denied {
            code: AuthzErrorCode::ConsentRequired,
            description: "consent is required but prompt=none forbids interaction",
        };
    }
    ConsentDecision::NeedsInteractiveConsent
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic clock for the fast-path expiry checks. All fixture consents
    /// either never expire or expire well after this instant.
    const NOW: i64 = 1_000_000;

    /// Build a recorded consent with the given granted scope that never expires.
    fn recorded(id: &str, granted_scope: Option<&str>) -> GrantedConsent {
        GrantedConsent {
            id: id.to_owned(),
            granted_scope: granted_scope.map(str::to_owned),
            expires_at_unix_micros: None,
        }
    }

    /// The base inputs a third-party non-quarantined explicit request with no recorded
    /// consent presents: the "needs consent" baseline every row perturbs from.
    fn base<'a>(
        cfg: &'a QuarantineConfig,
        effective_scope: Option<&'a str>,
        recorded: Option<&'a GrantedConsent>,
    ) -> ConsentInputs<'a> {
        ConsentInputs {
            client_quarantined: false,
            user_quarantined: false,
            prompt_consent: false,
            prompt_none: false,
            carveout_trusted: false,
            store_skipped_consent: false,
            unverified_sensitive_block: false,
            admin: AdminConsentOutcome::NotApplicable,
            recorded,
            effective_scope,
            consent_check_scope: effective_scope,
            now_micros: NOW,
            quarantine_cfg: cfg,
        }
    }

    /// Assert an [`ConsentDecision::AutoGrant`] with the expected bound scope and a
    /// [`ConsentRefAction`] matched by `ref_ok`.
    #[track_caller]
    fn assert_autogrant(
        decision: ConsentDecision,
        expected_scope: Option<&str>,
        ref_ok: impl FnOnce(&ConsentRefAction) -> bool,
    ) {
        match decision {
            ConsentDecision::AutoGrant {
                bound_scope,
                consent_ref,
            } => {
                assert_eq!(bound_scope.as_deref(), expected_scope, "bound scope");
                assert!(ref_ok(&consent_ref), "consent_ref action");
            }
            ConsentDecision::Denied { code, .. } => {
                panic!("expected AutoGrant, got Denied({code:?})")
            }
            ConsentDecision::NeedsInteractiveConsent => {
                panic!("expected AutoGrant, got NeedsInteractiveConsent")
            }
        }
    }

    #[test]
    fn third_party_with_no_consent_needs_the_screen() {
        // The baseline: an ordinary third-party explicit client with no recorded
        // consent must be shown the consent screen.
        let cfg = QuarantineConfig::default();
        let inputs = base(&cfg, Some("openid profile"), None);
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn prompt_none_without_consent_is_denied_consent_required() {
        // prompt=none turns the interaction need into a consent_required error, never a
        // rendered screen.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.prompt_none = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::Denied {
                code: AuthzErrorCode::ConsentRequired,
                ..
            }
        ));
    }

    #[test]
    fn consent_lockdown_denies_before_any_carve_out() {
        // The lockdown fires FIRST: even a trusted carve-out client with a covering
        // admin grant is denied when the lockdown flag is set.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("admin"), None);
        inputs.unverified_sensitive_block = true;
        inputs.carveout_trusted = true;
        inputs.admin = AdminConsentOutcome::Covered;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::Denied {
                code: AuthzErrorCode::AccessDenied,
                ..
            }
        ));
    }

    #[test]
    fn first_party_carve_out_audits_when_not_stored() {
        // A trusted carve-out client that does NOT store skipped consent auto-grants and
        // audits the skip (first_party_carveout), binding the full scope (user not
        // quarantined, so no strip).
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid offline_access"), None);
        inputs.carveout_trusted = true;
        assert_autogrant(decide(&inputs), Some("openid offline_access"), |action| {
            matches!(
                action,
                ConsentRefAction::AuditOnly {
                    reason: "first_party_carveout"
                }
            )
        });
    }

    #[test]
    fn first_party_carve_out_records_when_stored() {
        // The same carve-out with the store-skipped-consent knob on RECORDS the skip.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.carveout_trusted = true;
        inputs.store_skipped_consent = true;
        assert_autogrant(decide(&inputs), Some("openid"), |action| {
            matches!(action, ConsentRefAction::RecordSkipped)
        });
    }

    #[test]
    fn prompt_consent_forces_the_screen_over_the_carve_out() {
        // prompt=consent wins over the carve-out: a trusted carve-out client is still
        // shown a fresh screen.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.carveout_trusted = true;
        inputs.store_skipped_consent = true;
        inputs.prompt_consent = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn quarantined_client_never_gets_the_carve_out() {
        // A quarantined client's trust is ignored: force_consent is set, the carve-out is
        // disabled, and consent is shown.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.carveout_trusted = true;
        inputs.store_skipped_consent = true;
        inputs.client_quarantined = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn quarantined_user_never_gets_the_carve_out() {
        // A quarantined user also loses the carve-out (its trust is ignored), so consent
        // is shown even for a trusted client.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.carveout_trusted = true;
        inputs.store_skipped_consent = true;
        inputs.user_quarantined = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn recorded_consent_covering_the_scope_auto_grants() {
        // A fresh recorded consent that covers the checked scope auto-grants with the
        // recorded id, binding the full scope.
        let cfg = QuarantineConfig::default();
        let consent = recorded("con_recorded", Some("openid profile"));
        let inputs = base(&cfg, Some("openid profile"), Some(&consent));
        assert_autogrant(
            decide(&inputs),
            Some("openid profile"),
            |action| matches!(action, ConsentRefAction::UseRecorded(id) if id == "con_recorded"),
        );
    }

    #[test]
    fn recorded_consent_that_is_too_narrow_needs_the_screen() {
        // A consent recorded for a narrower scope (issue #196) does not cover a broader
        // request: re-prompt.
        let cfg = QuarantineConfig::default();
        let consent = recorded("con_narrow", Some("openid"));
        let inputs = base(&cfg, Some("openid profile"), Some(&consent));
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn recorded_consent_that_is_expired_needs_the_screen() {
        // A recorded consent past its expiry is treated as absent (issue #21).
        let cfg = QuarantineConfig::default();
        let consent = GrantedConsent {
            id: "con_expired".to_owned(),
            granted_scope: Some("openid".to_owned()),
            expires_at_unix_micros: Some(NOW - 1),
        };
        let inputs = base(&cfg, Some("openid"), Some(&consent));
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn prompt_consent_disables_the_recorded_fast_path() {
        // prompt=consent forces a fresh screen even when a covering consent is recorded.
        let cfg = QuarantineConfig::default();
        let consent = recorded("con_recorded", Some("openid"));
        let mut inputs = base(&cfg, Some("openid"), Some(&consent));
        inputs.prompt_consent = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn quarantined_user_with_recorded_consent_auto_grants_stripped() {
        // A quarantined user with a covering recorded consent still auto-grants (a fresh
        // consent completes the flow, no loop), but the sensitive scope is STRIPPED from
        // the bound scope, so offline_access can never reach the code.
        let cfg = QuarantineConfig::default();
        let consent = recorded("con_recorded", Some("openid offline_access"));
        let mut inputs = base(&cfg, Some("openid offline_access"), Some(&consent));
        inputs.user_quarantined = true;
        // consent_check_scope is the caller's responsibility; with offline_access still in
        // the check the recorded consent (granted openid offline_access) still covers it.
        assert_autogrant(
            decide(&inputs),
            Some("openid"),
            |action| matches!(action, ConsentRefAction::UseRecorded(id) if id == "con_recorded"),
        );
    }

    #[test]
    fn quarantined_user_strip_can_empty_the_bound_scope() {
        // When the only granted scope is sensitive, a quarantined user's bound scope is
        // the empty set (None), never a sensitive scope.
        let cfg = QuarantineConfig::default();
        let consent = recorded("con_recorded", Some("offline_access"));
        let mut inputs = base(&cfg, Some("offline_access"), Some(&consent));
        inputs.user_quarantined = true;
        assert_autogrant(decide(&inputs), None, |action| {
            matches!(action, ConsentRefAction::UseRecorded(_))
        });
    }

    #[test]
    fn admin_covered_skips_the_screen_and_audits() {
        // A third-party client with a covering admin pre-authorization skips the user
        // screen and audits admin_preauthorized (no consent row).
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid profile"), None);
        inputs.admin = AdminConsentOutcome::Covered;
        assert_autogrant(decide(&inputs), Some("openid profile"), |action| {
            matches!(
                action,
                ConsentRefAction::AuditOnly {
                    reason: "admin_preauthorized"
                }
            )
        });
    }

    #[test]
    fn admin_covered_but_forced_falls_through_to_the_screen() {
        // A covering admin grant does NOT grant screen invisibility: prompt=consent still
        // shows the screen (the request is allowed, not silently skipped).
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.admin = AdminConsentOutcome::Covered;
        inputs.prompt_consent = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn admin_covered_but_user_quarantined_falls_through_to_the_screen() {
        // A quarantined user with a covering admin grant is still shown consent (the
        // admin skip is disabled), and the request is not otherwise auto-granted.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.admin = AdminConsentOutcome::Covered;
        inputs.user_quarantined = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::NeedsInteractiveConsent
        ));
    }

    #[test]
    fn admin_requires_approval_is_a_terminal_deny() {
        // An uncovered third-party request is a terminal access_denied, the same under
        // prompt=none.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.admin = AdminConsentOutcome::RequiresAdminApproval;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::Denied {
                code: AuthzErrorCode::AccessDenied,
                ..
            }
        ));
        inputs.prompt_none = true;
        assert!(matches!(
            decide(&inputs),
            ConsentDecision::Denied {
                code: AuthzErrorCode::AccessDenied,
                ..
            }
        ));
    }

    #[test]
    fn admin_covered_wins_over_a_trusted_carve_out_ref() {
        // Ordering: the admin gate fires BEFORE the first-party carve-out. A covering
        // grant on a trusted client audits admin_preauthorized, not first_party_carveout.
        let cfg = QuarantineConfig::default();
        let mut inputs = base(&cfg, Some("openid"), None);
        inputs.admin = AdminConsentOutcome::Covered;
        inputs.carveout_trusted = true;
        inputs.store_skipped_consent = true;
        assert_autogrant(decide(&inputs), Some("openid"), |action| {
            matches!(
                action,
                ConsentRefAction::AuditOnly {
                    reason: "admin_preauthorized"
                }
            )
        });
    }
}
