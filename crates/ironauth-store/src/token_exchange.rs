// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8693 token-exchange narrowing and mode policy (issue #125).
//!
//! Issue #125 lists three modes "with downscoping as the safe default", and requires "no ambient
//! trust, structurally". This is the pure decision core for both: given what the SUBJECT token
//! actually carries, what the client asked for, and the client's configured policy, decide what
//! may be issued.
//!
//! Token validation itself (signature, expiry, revocation, tenant and organization boundary) is
//! not here and must happen before this is called. This module deliberately takes only ALREADY
//! VALIDATED facts, which is what makes "no field is trusted because a prior handler validated
//! it" checkable: there is no request field in scope here that could be trusted by accident.
//!
//! # Narrowing is the default, and widening is not an error to be handled but a request to be
//! refused
//!
//! An exchange may narrow scope, audience and resource. It may never widen any of them. That is
//! the property that makes token exchange safe to expose at all: a client holding a token can
//! only ever trade it for something weaker, so a compromised downstream service cannot escalate
//! by asking politely.
//!
//! The subtle case, and the one worth writing a test for, is the ABSENT scope parameter. RFC
//! 8693 section 2.1 says omitting `scope` means the authorization server decides. Reading that
//! as "grant everything the subject has" is defensible and is what this does; reading it as
//! "grant everything the CLIENT could ever have" would be a silent escalation triggered by
//! leaving a parameter out, which is the worst possible ergonomics for a security boundary.
//!
//! # Impersonation is denied unless configured, and that asymmetry is deliberate
//!
//! Delegation keeps the actor VISIBLE in the issued token (`act`), so an audit trail survives
//! the hop. Impersonation erases the actor: the issued token looks exactly like one the subject
//! obtained themselves. That is occasionally necessary and always dangerous, so it requires
//! explicit per-client configuration and this core refuses it by default.

use std::collections::BTreeSet;

/// Which RFC 8693 mode an exchange is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeMode {
    /// Trade a token for a strictly weaker one for the same subject. No actor token.
    Downscope,
    /// A actor acts ON BEHALF OF the subject, and stays visible in the issued token's `act`
    /// chain.
    Delegation,
    /// The actor becomes indistinguishable from the subject. The actor is NOT recorded in the
    /// token, which is exactly why it is dangerous.
    Impersonation,
    /// A Native SSO bootstrap (issue #133, PROTOTYPE): a sibling app on the same device trades
    /// the family's ID token plus its device secret for its own tokens.
    ///
    /// Its OWN mode rather than one of the three above, and that is the point. By shape it
    /// looks like an impersonation -- another client's token, no actor recorded -- so it would
    /// otherwise be default-denied unless the operator set `token_exchange_impersonation_
    /// allowed` on every sibling app. That flag is not scoped to this feature: once set, the
    /// app may present ANY client's token for ANY subject. Making a device-secret bootstrap
    /// require the broadest privilege in the exchange, in order to do something far narrower,
    /// would be a worse trade than the feature is worth.
    ///
    /// What authorizes it instead is the DEVICE SECRET, which the caller verified against the
    /// ID token's `ds_hash` before this mode can be constructed at all. This variant is
    /// reachable only from that path.
    NativeSsoBootstrap,
}

/// Why an exchange was refused.
///
/// Distinct variants for the admin log. RFC 8693 section 2.2.2 requires the WIRE error to be
/// opaque, and issue #125 says so explicitly ("out-of-band diagnostics in the admin log view,
/// opaque errors on the wire"), so these must never be serialised into a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeDenial {
    /// The request asked for scope the subject token does not carry.
    ScopeWidened(BTreeSet<String>),
    /// The request asked for an audience the subject token is not valid for.
    AudienceWidened(BTreeSet<String>),
    /// Impersonation was requested and this client is not configured for it.
    ImpersonationNotAllowed,
    /// Delegation was requested without an actor token, or impersonation with one. The mode and
    /// the presented tokens have to agree.
    ModeTokenMismatch,
    /// The subject token carries no scope at all, so there is nothing to narrow from.
    SubjectHasNoScope,
}

impl ExchangeDenial {
    /// A stable, value-free label for metrics and logs. Never returned to a client.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ScopeWidened(_) => "the request asked for scope the subject token lacks",
            Self::AudienceWidened(_) => "the request asked for an audience the subject lacks",
            Self::ImpersonationNotAllowed => "impersonation is not enabled for this client",
            Self::ModeTokenMismatch => "the requested mode and the presented tokens disagree",
            Self::SubjectHasNoScope => "the subject token carries no scope to narrow from",
        }
    }
}

/// The already-validated facts an exchange decision is made from.
#[derive(Debug, Clone)]
pub struct ExchangeRequest {
    /// Scopes the SUBJECT token actually carries, from the validated token.
    pub subject_scope: BTreeSet<String>,
    /// Audiences the SUBJECT token is valid for, from the validated token.
    pub subject_audience: BTreeSet<String>,
    /// Scopes requested, or empty when the parameter was omitted.
    pub requested_scope: BTreeSet<String>,
    /// Audiences requested, or empty when omitted.
    pub requested_audience: BTreeSet<String>,
    /// Whether an actor token was presented AND validated.
    pub actor_present: bool,
    /// The mode the client asked for.
    pub mode: ExchangeMode,
}

/// What an exchange is permitted to issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeGrant {
    /// The scope the issued token carries.
    pub scope: BTreeSet<String>,
    /// The audience the issued token is restricted to.
    pub audience: BTreeSet<String>,
    /// Whether the issued token must carry an `act` claim naming the actor.
    ///
    /// True for delegation only. Impersonation deliberately does NOT set it, which is the
    /// difference between the two modes and the reason impersonation needs configuration.
    pub records_actor: bool,
}

/// Decide what this exchange may issue.
///
/// # Errors
///
/// [`ExchangeDenial`] naming the first rule that refused, checked in the order a reviewer would.
pub fn decide_exchange(
    request: &ExchangeRequest,
    impersonation_allowed: bool,
) -> Result<ExchangeGrant, ExchangeDenial> {
    // Mode and tokens must agree BEFORE anything else. A delegation without an actor token has
    // nobody to record in `act`, and an impersonation WITH one is a contradiction: the caller
    // both named an actor and asked for the actor to be erased.
    // An actor token is present IF AND ONLY IF this is a delegation. Stated as one biconditional
    // rather than three arms, because that is precisely the rule: delegation is the only mode
    // with an actor to record, so an actor token anywhere else is a request that contradicts
    // itself, and delegation without one has nobody to put in `act`.
    let actor_expected = request.mode == ExchangeMode::Delegation;
    if request.actor_present != actor_expected {
        return Err(ExchangeDenial::ModeTokenMismatch);
    }

    // Default deny. An operator turns this on per client; nothing about holding a valid token
    // implies it.
    //
    // `NativeSsoBootstrap` is deliberately NOT folded in here. It is impersonation-shaped, and
    // routing it through this flag would mean arming a mobile SSO feature by granting every
    // sibling app the right to present any client's token for any subject. Its authorization is
    // the device secret, checked before the mode exists; see the variant's doc.
    if request.mode == ExchangeMode::Impersonation && !impersonation_allowed {
        return Err(ExchangeDenial::ImpersonationNotAllowed);
    }

    if request.subject_scope.is_empty() {
        return Err(ExchangeDenial::SubjectHasNoScope);
    }

    // An OMITTED scope means "what the subject already has", never "everything this client
    // could have". Reading it the other way would make leaving a parameter out an escalation.
    let scope = if request.requested_scope.is_empty() {
        request.subject_scope.clone()
    } else {
        let widened: BTreeSet<String> = request
            .requested_scope
            .difference(&request.subject_scope)
            .cloned()
            .collect();
        if !widened.is_empty() {
            return Err(ExchangeDenial::ScopeWidened(widened));
        }
        request.requested_scope.clone()
    };

    // Audience narrows by exactly the same rule, and for the same reason: an exchange that
    // could add an audience would let a token minted for one service be traded for one that
    // another service accepts.
    //
    // A NATIVE SSO BOOTSTRAP is the one mode this rule does not describe. It is not narrowing an
    // existing token's audience: the sibling is receiving its OWN first token, so app A's
    // audience is not a ceiling on it, it is simply somebody else's. Constraining to it gave the
    // sibling a token audienced to APP A -- exactly the shape impersonation is gated for -- and
    // made every `audience`/`resource` the sibling named an `invalid_target`, so it could never
    // obtain a usable token at all. Its audience is resolved for the REQUESTING client by the
    // caller, from the same resource-indicator path any other first issuance uses.
    let audience = if request.mode == ExchangeMode::NativeSsoBootstrap {
        request.requested_audience.clone()
    } else if request.requested_audience.is_empty() {
        request.subject_audience.clone()
    } else {
        let widened: BTreeSet<String> = request
            .requested_audience
            .difference(&request.subject_audience)
            .cloned()
            .collect();
        if !widened.is_empty() {
            return Err(ExchangeDenial::AudienceWidened(widened));
        }
        request.requested_audience.clone()
    };

    Ok(ExchangeGrant {
        scope,
        audience,
        records_actor: request.mode == ExchangeMode::Delegation,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ExchangeDenial, ExchangeGrant, ExchangeMode, ExchangeRequest, decide_exchange};

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn request(mode: ExchangeMode) -> ExchangeRequest {
        ExchangeRequest {
            subject_scope: set(&["read", "write", "admin"]),
            subject_audience: set(&["api-a", "api-b"]),
            requested_scope: BTreeSet::new(),
            requested_audience: BTreeSet::new(),
            actor_present: mode == ExchangeMode::Delegation,
            mode,
        }
    }

    #[test]
    fn a_native_sso_bootstrap_needs_no_actor_and_records_none() {
        // The mode exists to avoid riding the impersonation flag, so the two properties that
        // keep it from BEING an impersonation are pinned here, in the crate whose whole value
        // is being decidable without a database.
        let input = request(ExchangeMode::NativeSsoBootstrap);
        assert!(!input.actor_present, "a bootstrap presents no actor TOKEN");
        let grant =
            decide_exchange(&input, false).expect("a bootstrap needs no impersonation flag");
        assert!(
            !grant.records_actor,
            "and records no `act`: the device secret is not a party acting for the person"
        );
        assert_eq!(
            grant.scope,
            set(&["read", "write", "admin"]),
            "an omitted scope inherits the sign-in's, exactly as every other mode does"
        );
    }

    #[test]
    fn a_native_sso_bootstrap_is_refused_when_an_actor_token_rides_along() {
        // The biconditional still holds for the new mode. A bootstrap carrying an actor token
        // is a request contradicting itself, and admitting it would put the DEVICE SECRET in
        // the `act` chain.
        let mut input = request(ExchangeMode::NativeSsoBootstrap);
        input.actor_present = true;
        assert_eq!(
            decide_exchange(&input, false),
            Err(ExchangeDenial::ModeTokenMismatch)
        );
    }

    #[test]
    fn a_native_sso_bootstrap_is_not_bounded_by_the_subject_tokens_audience() {
        // THE FIX FOR A REAL DEFECT. A bootstrap is not narrowing an existing token: the
        // sibling receives its OWN first token, so app A's audience is somebody else's rather
        // than a ceiling. Constraining to it gave the sibling a token audienced to APP A and
        // turned every target it named into an `invalid_target`.
        let mut input = request(ExchangeMode::NativeSsoBootstrap);
        input.requested_audience = set(&["api-of-its-own"]);
        let grant = decide_exchange(&input, false).expect("its own audience is not a widening");
        assert_eq!(grant.audience, set(&["api-of-its-own"]));

        // And with none named the decision carries none, so the caller keeps the audience it
        // resolved for the requesting client rather than overwriting it with an empty set.
        let none = decide_exchange(&request(ExchangeMode::NativeSsoBootstrap), false)
            .expect("no target named is not a widening either");
        assert!(none.audience.is_empty());

        // The rule is UNCHANGED for every other mode: a downscope naming an audience the
        // subject lacks is still a widening.
        let mut downscope = request(ExchangeMode::Downscope);
        downscope.requested_audience = set(&["api-of-its-own"]);
        assert_eq!(
            decide_exchange(&downscope, false),
            Err(ExchangeDenial::AudienceWidened(set(&["api-of-its-own"])))
        );
    }

    #[test]
    fn a_downscope_narrows_and_issues_the_narrower_set() {
        let mut input = request(ExchangeMode::Downscope);
        input.requested_scope = set(&["read"]);
        input.requested_audience = set(&["api-a"]);
        assert_eq!(
            decide_exchange(&input, false).expect("permitted"),
            ExchangeGrant {
                scope: set(&["read"]),
                audience: set(&["api-a"]),
                records_actor: false,
            }
        );
    }

    /// THE property that makes token exchange safe to expose: it can only ever weaken.
    #[test]
    fn scope_can_never_be_widened() {
        let mut input = request(ExchangeMode::Downscope);
        input.requested_scope = set(&["read", "superuser"]);
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::ScopeWidened(set(&["superuser"])),
        );
        // The denial names exactly what was refused, so an operator reading the admin log can
        // see which scope a client is reaching for rather than only that something failed.
    }

    #[test]
    fn audience_can_never_be_widened() {
        let mut input = request(ExchangeMode::Downscope);
        input.requested_audience = set(&["api-a", "api-c"]);
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::AudienceWidened(set(&["api-c"])),
        );
    }

    /// An OMITTED scope means what the subject already has, never everything the client could.
    ///
    /// Reading it the other way would make leaving a parameter out an escalation, which is the
    /// worst possible ergonomics for a security boundary.
    #[test]
    fn an_omitted_scope_inherits_the_subjects_and_does_not_escalate() {
        let input = request(ExchangeMode::Downscope);
        let grant = decide_exchange(&input, false).expect("permitted");
        assert_eq!(grant.scope, set(&["read", "write", "admin"]));
        assert_eq!(grant.audience, set(&["api-a", "api-b"]));
    }

    /// Impersonation is denied by default. Holding a valid token implies nothing.
    #[test]
    fn impersonation_is_denied_unless_configured() {
        let input = request(ExchangeMode::Impersonation);
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::ImpersonationNotAllowed,
        );
        // The identical request with the policy enabled succeeds, so the refusal is the policy
        // and not some other defect in the fixture.
        assert!(decide_exchange(&input, true).is_ok());
    }

    /// Delegation records the actor; impersonation deliberately does not.
    ///
    /// That single flag IS the difference between the two modes, and it is why impersonation
    /// needs configuration: it erases the audit trail the other mode preserves.
    #[test]
    fn only_delegation_records_the_actor() {
        let delegation =
            decide_exchange(&request(ExchangeMode::Delegation), false).expect("permitted");
        assert!(delegation.records_actor, "the actor must stay visible");

        let impersonation =
            decide_exchange(&request(ExchangeMode::Impersonation), true).expect("permitted");
        assert!(
            !impersonation.records_actor,
            "impersonation erases the actor, which is exactly why it is configured"
        );

        let downscope =
            decide_exchange(&request(ExchangeMode::Downscope), false).expect("permitted");
        assert!(!downscope.records_actor, "there is no actor to record");
    }

    /// The mode and the presented tokens have to agree, in both directions.
    #[test]
    fn the_mode_and_the_actor_token_must_agree() {
        // Delegation with no actor token: nobody to put in `act`.
        let mut input = request(ExchangeMode::Delegation);
        input.actor_present = false;
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::ModeTokenMismatch
        );

        // Impersonation WITH an actor token: the caller named an actor and asked for the actor
        // to be erased, which is a contradiction rather than a preference.
        let mut input = request(ExchangeMode::Impersonation);
        input.actor_present = true;
        assert_eq!(
            decide_exchange(&input, true).unwrap_err(),
            ExchangeDenial::ModeTokenMismatch
        );

        // A plain downscope with an actor token is likewise incoherent.
        let mut input = request(ExchangeMode::Downscope);
        input.actor_present = true;
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::ModeTokenMismatch
        );
    }

    /// The mode check runs BEFORE the impersonation policy, so a contradictory request is
    /// refused as incoherent rather than reported as a policy problem an operator might "fix"
    /// by enabling impersonation.
    #[test]
    fn an_incoherent_request_is_not_reported_as_a_policy_denial() {
        let mut input = request(ExchangeMode::Impersonation);
        input.actor_present = true;
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::ModeTokenMismatch,
            "enabling impersonation would not make this request coherent"
        );
    }

    #[test]
    fn a_subject_with_no_scope_has_nothing_to_narrow() {
        let mut input = request(ExchangeMode::Downscope);
        input.subject_scope = BTreeSet::new();
        assert_eq!(
            decide_exchange(&input, false).unwrap_err(),
            ExchangeDenial::SubjectHasNoScope
        );
    }

    /// Requesting exactly what the subject has is a narrowing of zero, and permitted.
    #[test]
    fn requesting_the_full_subject_scope_is_allowed() {
        let mut input = request(ExchangeMode::Downscope);
        input.requested_scope = set(&["read", "write", "admin"]);
        assert_eq!(
            decide_exchange(&input, false).expect("permitted").scope,
            set(&["read", "write", "admin"])
        );
    }

    /// Every denial describes itself distinctly, for the admin log. These must never reach the
    /// wire: RFC 8693 2.2.2 and issue #125 both require the client-visible error to be opaque.
    #[test]
    fn every_denial_describes_itself_distinctly() {
        let all = [
            ExchangeDenial::ScopeWidened(set(&["x"])),
            ExchangeDenial::AudienceWidened(set(&["x"])),
            ExchangeDenial::ImpersonationNotAllowed,
            ExchangeDenial::ModeTokenMismatch,
            ExchangeDenial::SubjectHasNoScope,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for denial in &all {
            assert!(denial.as_str().len() > 20, "{denial:?} has no useful text");
            assert!(seen.insert(denial.as_str()), "{denial:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
