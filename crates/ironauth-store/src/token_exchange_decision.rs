// SPDX-License-Identifier: MIT OR Apache-2.0

//! The composed token-exchange decision (issue #125).
//!
//! Four cores landed separately: [`grant_restriction`](crate::grant_restriction) decides whether
//! the client may use this grant at all, [`token_exchange`](crate::token_exchange) narrows scope
//! and audience and picks the mode, [`token_type_negotiation`](crate::token_type_negotiation)
//! decides what is issued, and [`token_act_chain`](crate::token_act_chain) builds the delegation
//! record. Each was tested alone and none called any other.
//!
//! Four correct modules that never meet are four modules that might not FIT, and the message
//! modules already demonstrated where that bites: three of the eight mutations against their
//! composition were only expressible at the seam, invisible from inside any single module.
//! This is the same seam for the exchange path, and it exists before the token endpoint wiring
//! precisely so the ordering is settled and tested while it is still cheap to change.
//!
//! # The ordering is the security property
//!
//! Every step is a refusal opportunity, and the order decides which refusal a caller learns
//! about. Two orderings are load bearing:
//!
//! - **Grant restriction runs FIRST**, before any token content is examined. A client not
//!   registered for `token-exchange` must be refused for that reason and no other. Running the
//!   narrowing first would tell an unregistered client which scopes its token carries and which
//!   it may not ask for, which is a probe the seam exists to prevent.
//! - **Narrowing runs before type negotiation.** A request that both widens scope AND asks for
//!   an unconfigured refresh token is refused for the widening, because that is the more serious
//!   attempt: one is a client asking for a feature, the other is a client reaching for authority
//!   it does not have.
//!
//! # No IO, still
//!
//! Token validation, revocation checks and the audit write are the caller's. This takes only
//! already-validated facts, which is what keeps issue #125's "no field is trusted because a
//! prior handler validated it" checkable: there is no raw request field in scope here.

use serde_json::Value;

use crate::grant_restriction::{ClientGrantPolicy, GrantDenial, GrantType, client_may_use};
use crate::token_act_chain::{ActChainError, extend_act_chain};
use crate::token_exchange::{ExchangeDenial, ExchangeRequest, decide_exchange};
use crate::token_type_negotiation::{
    DefaultAccessFormat, IssuedTokenType, TypeDenial, negotiate_type,
};

/// Why an exchange was refused, carrying which stage refused it.
///
/// The stages are distinct types rather than one flattened enum, because each already has a
/// documented vocabulary and collapsing them would lose which layer objected. RFC 8693 2.2.2
/// requires the WIRE error to be opaque; every variant here is for the admin log only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeRefusal {
    /// The client may not use the token-exchange grant at all.
    Grant(GrantDenial),
    /// The requested scope, audience or mode was refused.
    Narrowing(ExchangeDenial),
    /// The requested token type was refused.
    TokenType(TypeDenial),
    /// The delegation chain could not be extended.
    ActChain(ActChainError),
}

/// Everything one exchange decision needs, all already validated.
pub struct ExchangeDecisionInput<'a> {
    /// What the client is registered for.
    pub client_policy: &'a ClientGrantPolicy,
    /// Whether this client may impersonate.
    pub impersonation_allowed: bool,
    /// Whether this client may receive a refresh token from an exchange.
    pub refresh_allowed: bool,
    /// The client's default access-token format.
    pub default_format: DefaultAccessFormat,
    /// The narrowing request, built from the validated subject token.
    pub exchange: ExchangeRequest,
    /// The `requested_token_type` parameter, or [`None`].
    pub requested_type: Option<&'a str>,
    /// The subject token's existing `act` chain, if any.
    pub existing_act: Option<&'a Value>,
    /// The subject of the VALIDATED actor token, for delegation.
    pub actor_subject: Option<&'a str>,
}

/// Everything an exchange will issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeDecision {
    /// The scope of the issued token.
    pub scope: std::collections::BTreeSet<String>,
    /// The audience of the issued token.
    pub audience: std::collections::BTreeSet<String>,
    /// What kind of token to mint.
    pub token_type: IssuedTokenType,
    /// The `act` claim, present only for delegation.
    pub act: Option<Value>,
}

/// Decide an exchange end to end.
///
/// # Errors
///
/// [`ExchangeRefusal`] naming the stage that refused. See the module documentation for why the
/// stage order is what it is.
pub fn decide(input: &ExchangeDecisionInput<'_>) -> Result<ExchangeDecision, ExchangeRefusal> {
    // FIRST, before any token content is looked at. A client not registered for this grant is
    // refused for that reason and learns nothing about its token's scopes.
    client_may_use(input.client_policy, GrantType::TokenExchange)
        .map_err(ExchangeRefusal::Grant)?;

    let grant = decide_exchange(&input.exchange, input.impersonation_allowed)
        .map_err(ExchangeRefusal::Narrowing)?;

    let token_type = negotiate_type(
        input.requested_type,
        input.refresh_allowed,
        input.default_format,
    )
    .map_err(ExchangeRefusal::TokenType)?;

    // The chain is extended ONLY for delegation, and only from the validated actor token.
    //
    // A missing subject here would be a bug rather than a request: the narrowing stage already
    // refused a delegation without an actor token. It is matched rather than unwrapped so the
    // bug cannot become a panic in the token endpoint.
    //
    // What actually GUARANTEES the empty case is refused is `extend_act_chain`, which rejects
    // an empty actor itself. Measured, not assumed: replacing this match with
    // `unwrap_or("")` survives the suite, because both routes reach the same
    // `ActChainError::EmptyActor`. The match is kept for locality, not because correctness
    // rests on it.
    let act = if grant.records_actor {
        let Some(actor) = input.actor_subject else {
            return Err(ExchangeRefusal::ActChain(ActChainError::EmptyActor));
        };
        Some(extend_act_chain(input.existing_act, actor).map_err(ExchangeRefusal::ActChain)?)
    } else {
        None
    };

    Ok(ExchangeDecision {
        scope: grant.scope,
        audience: grant.audience,
        token_type,
        act,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::{ExchangeDecisionInput, ExchangeRefusal, decide};
    use crate::grant_restriction::{ClientGrantPolicy, GrantDenial, GrantType};
    use crate::token_act_chain::ActChainError;
    use crate::token_exchange::{ExchangeDenial, ExchangeMode, ExchangeRequest};
    use crate::token_type_negotiation::{
        DefaultAccessFormat, IssuedTokenType, TypeDenial, type_uri,
    };

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn policy() -> ClientGrantPolicy {
        ClientGrantPolicy {
            allowed: vec![GrantType::TokenExchange],
            confidential: true,
        }
    }

    fn exchange(mode: ExchangeMode) -> ExchangeRequest {
        ExchangeRequest {
            subject_scope: set(&["read", "write"]),
            subject_audience: set(&["api-a"]),
            requested_scope: BTreeSet::new(),
            requested_audience: BTreeSet::new(),
            actor_present: mode == ExchangeMode::Delegation,
            mode,
        }
    }

    fn input<'a>(
        client_policy: &'a ClientGrantPolicy,
        exchange: ExchangeRequest,
        actor: Option<&'a str>,
    ) -> ExchangeDecisionInput<'a> {
        ExchangeDecisionInput {
            client_policy,
            impersonation_allowed: false,
            refresh_allowed: false,
            default_format: DefaultAccessFormat::Jwt,
            exchange,
            requested_type: None,
            existing_act: None,
            actor_subject: actor,
        }
    }

    #[test]
    fn a_plain_downscope_composes_end_to_end() {
        let client = policy();
        let decision =
            decide(&input(&client, exchange(ExchangeMode::Downscope), None)).expect("permitted");
        assert_eq!(decision.scope, set(&["read", "write"]));
        assert_eq!(decision.audience, set(&["api-a"]));
        assert_eq!(decision.token_type, IssuedTokenType::AccessTokenJwt);
        assert!(decision.act.is_none(), "there is no actor to record");
    }

    /// A delegation carries the act chain through the composition, built from the actor token.
    #[test]
    fn a_delegation_records_the_actor_in_the_chain() {
        let client = policy();
        let decision = decide(&input(
            &client,
            exchange(ExchangeMode::Delegation),
            Some("svc-b"),
        ))
        .expect("permitted");
        assert_eq!(decision.act, Some(json!({"sub": "svc-b"})));
    }

    /// A multi-hop delegation nests, most recent outermost, through the composition.
    #[test]
    fn a_multi_hop_delegation_nests_through_the_composition() {
        let client = policy();
        let existing = json!({"sub": "svc-a"});
        let mut request = input(&client, exchange(ExchangeMode::Delegation), Some("svc-b"));
        request.existing_act = Some(&existing);
        let decision = decide(&request).expect("permitted");
        assert_eq!(
            decision.act,
            Some(json!({"sub": "svc-b", "act": {"sub": "svc-a"}}))
        );
    }

    /// THE ordering property: grant restriction runs FIRST.
    ///
    /// A client not registered for token-exchange must be refused for that reason and learn
    /// nothing about its token's scopes. Running narrowing first would tell an unregistered
    /// client which scopes it carries and which it may not ask for.
    #[test]
    fn an_unregistered_client_is_refused_before_any_token_content_is_examined() {
        let unregistered = ClientGrantPolicy {
            allowed: vec![GrantType::AuthorizationCode],
            confidential: true,
        };
        // This request ALSO widens scope, which the narrowing stage would refuse. The grant
        // refusal must win, so the client cannot use a deliberately invalid narrowing request
        // to discover whether it is registered.
        let mut widening = exchange(ExchangeMode::Downscope);
        widening.requested_scope = set(&["read", "superuser"]);
        assert_eq!(
            decide(&input(&unregistered, widening, None)).unwrap_err(),
            ExchangeRefusal::Grant(GrantDenial::NotRegistered)
        );
    }

    /// A public client is refused at the grant stage too, before anything else.
    #[test]
    fn a_public_client_is_refused_at_the_grant_stage() {
        let public = ClientGrantPolicy {
            allowed: vec![GrantType::TokenExchange],
            confidential: false,
        };
        assert_eq!(
            decide(&input(&public, exchange(ExchangeMode::Downscope), None)).unwrap_err(),
            ExchangeRefusal::Grant(GrantDenial::RequiresConfidentialClient)
        );
    }

    /// Narrowing runs BEFORE type negotiation, so a request that both widens scope and asks for
    /// an unconfigured refresh token is refused for the WIDENING.
    ///
    /// That is the more serious attempt: one is a client asking for a feature, the other is a
    /// client reaching for authority it does not have.
    #[test]
    fn a_widening_request_is_refused_before_the_token_type() {
        let client = policy();
        let mut widening = exchange(ExchangeMode::Downscope);
        widening.requested_scope = set(&["read", "superuser"]);
        let mut request = input(&client, widening, None);
        request.requested_type = Some(type_uri::REFRESH_TOKEN);
        assert_eq!(
            decide(&request).unwrap_err(),
            ExchangeRefusal::Narrowing(ExchangeDenial::ScopeWidened(set(&["superuser"])))
        );
    }

    /// The type stage still refuses when narrowing passes, so it is genuinely reached.
    #[test]
    fn an_unconfigured_refresh_token_is_refused_once_narrowing_passes() {
        let client = policy();
        let mut request = input(&client, exchange(ExchangeMode::Downscope), None);
        request.requested_type = Some(type_uri::REFRESH_TOKEN);
        assert_eq!(
            decide(&request).unwrap_err(),
            ExchangeRefusal::TokenType(TypeDenial::RefreshNotAllowed)
        );
        // And it is permitted once configured, so the refusal was the policy.
        request.refresh_allowed = true;
        assert_eq!(
            decide(&request).expect("permitted").token_type,
            IssuedTokenType::RefreshToken
        );
    }

    /// Impersonation is refused by the narrowing stage unless configured, through the
    /// composition, and records no actor when it is allowed.
    #[test]
    fn impersonation_is_refused_unless_configured_and_records_no_actor() {
        let client = policy();
        let mut request = input(&client, exchange(ExchangeMode::Impersonation), None);
        assert_eq!(
            decide(&request).unwrap_err(),
            ExchangeRefusal::Narrowing(ExchangeDenial::ImpersonationNotAllowed)
        );
        request.impersonation_allowed = true;
        let decision = decide(&request).expect("permitted");
        assert!(
            decision.act.is_none(),
            "impersonation erases the actor, which is why it needs configuration"
        );
    }

    /// A delegation reaching the chain stage without an actor subject is a BUG, and is handled
    /// rather than unwrapped so it cannot become a panic in the token endpoint.
    ///
    /// The narrowing stage already refuses a delegation with no actor token, so this is
    /// unreachable through the normal path; the test drives it directly to prove the handling
    /// exists.
    #[test]
    fn a_delegation_without_an_actor_subject_is_an_error_not_a_panic() {
        let client = policy();
        // actor_present is true so narrowing passes, but no subject is supplied.
        let decision = decide(&input(&client, exchange(ExchangeMode::Delegation), None));
        assert_eq!(
            decision.unwrap_err(),
            ExchangeRefusal::ActChain(ActChainError::EmptyActor)
        );
    }

    /// Each stage's refusal keeps its own vocabulary, so the admin log says which layer
    /// objected rather than flattening four documented vocabularies into one.
    #[test]
    fn refusals_name_the_stage_that_refused() {
        let client = policy();
        let public = ClientGrantPolicy {
            allowed: vec![GrantType::TokenExchange],
            confidential: false,
        };
        let grant = decide(&input(&public, exchange(ExchangeMode::Downscope), None)).unwrap_err();
        let mut widening = exchange(ExchangeMode::Downscope);
        widening.requested_scope = set(&["nope"]);
        let narrowing = decide(&input(&client, widening, None)).unwrap_err();
        assert!(matches!(grant, ExchangeRefusal::Grant(_)));
        assert!(matches!(narrowing, ExchangeRefusal::Narrowing(_)));
        assert_ne!(grant, narrowing);
    }
}
