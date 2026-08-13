// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8693 `act` delegation chain (issue #125).
//!
//! Issue #125 asks for "act claim chains with composable act.act nesting across multi-hop calls
//! per RFC 8693 section 4.1; the actor stays visible in the issued token and in introspection".
//! This builds that claim, purely.
//!
//! # The nesting order is the meaning, and it is easy to invert
//!
//! RFC 8693 section 4.1 nests `act` so the **most recent** actor is OUTERMOST and each `act.act`
//! is the party that delegated to it. Reading a chain outward-in gives you "who is acting right
//! now, on behalf of whom, on behalf of whom".
//!
//! Inverting that does not produce an obviously broken token. It produces a well-formed one
//! that names the wrong party as the current actor, so an audit trail reads backwards and an
//! authorization decision made on "the immediate actor" picks the party furthest from the
//! request. That is why the ordering has its own test rather than being implied by a round trip.
//!
//! # The chain comes from tokens, never from parameters
//!
//! Every actor in a chain arrives from a VALIDATED actor token. Nothing here accepts an actor
//! identity as a request field, because a caller able to name its own position in the chain
//! could insert a party that never delegated anything, and the claim exists precisely to be
//! trustworthy about that.
//!
//! # Depth is capped, and the cap is a security control rather than a limit
//!
//! Each hop nests one level deeper and the token grows. Uncapped, a delegation loop between two
//! services inflates a token until something downstream refuses it, and the failure surfaces far
//! from the cause. [`MAX_ACT_DEPTH`] refuses the exchange instead, at the hop that would have
//! exceeded it, where the responsible party is still visible.

use serde_json::{Map, Value, json};

/// How many actors a delegation chain may contain.
///
/// Eight is far beyond any legitimate topology (a request crossing eight delegating services is
/// already a design problem) and low enough that a runaway loop is refused while the token is
/// still small. The number matters less than that there IS one: uncapped, the failure arrives
/// as an opaque size rejection several services away from the loop that caused it.
pub const MAX_ACT_DEPTH: usize = 8;

/// Why a chain could not be extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActChainError {
    /// Adding this actor would exceed [`MAX_ACT_DEPTH`].
    TooDeep,
    /// The actor's subject is empty, which would produce a chain link identifying nobody.
    EmptyActor,
    /// The existing chain is not the shape RFC 8693 defines.
    MalformedChain,
}

impl ActChainError {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TooDeep => "the delegation chain is deeper than the configured maximum",
            Self::EmptyActor => "an actor in the chain has no subject",
            Self::MalformedChain => "the existing act chain is not the RFC 8693 shape",
        }
    }
}

/// Extend a delegation chain with a new, most-recent actor.
///
/// `existing` is the `act` claim from the SUBJECT token, or [`None`] on the first hop.
/// `actor_subject` is the subject of the VALIDATED actor token.
///
/// The result is the new `act` claim: `actor_subject` outermost, `existing` nested beneath it as
/// `act`.
///
/// # Errors
///
/// [`ActChainError`] when the actor is empty, the existing chain is malformed, or the result
/// would exceed [`MAX_ACT_DEPTH`].
pub fn extend_act_chain(
    existing: Option<&Value>,
    actor_subject: &str,
) -> Result<Value, ActChainError> {
    if actor_subject.trim().is_empty() {
        return Err(ActChainError::EmptyActor);
    }
    let depth = match existing {
        None => 0,
        Some(chain) => chain_depth(chain)?,
    };
    if depth + 1 > MAX_ACT_DEPTH {
        return Err(ActChainError::TooDeep);
    }

    let mut link = Map::new();
    link.insert("sub".to_owned(), json!(actor_subject));
    if let Some(chain) = existing {
        // The PREVIOUS chain nests INSIDE the new actor, so the new actor is outermost and the
        // chain reads outward-in as most-recent-first. Nesting the other way round produces a
        // well-formed token that names the wrong party as the current actor.
        link.insert("act".to_owned(), chain.clone());
    }
    Ok(Value::Object(link))
}

/// How many actors a chain contains.
///
/// # Errors
///
/// [`ActChainError::MalformedChain`] if any link is not an object with a non-empty string `sub`,
/// or if the nesting is already deeper than [`MAX_ACT_DEPTH`]. A chain that arrived over-deep is
/// refused rather than counted, because counting it would mean walking whatever depth an
/// attacker supplied.
pub fn chain_depth(chain: &Value) -> Result<usize, ActChainError> {
    let mut depth = 0_usize;
    let mut current = chain;
    loop {
        let Some(object) = current.as_object() else {
            return Err(ActChainError::MalformedChain);
        };
        match object.get("sub").and_then(Value::as_str) {
            Some(subject) if !subject.trim().is_empty() => {}
            _ => return Err(ActChainError::MalformedChain),
        }
        depth += 1;
        if depth > MAX_ACT_DEPTH {
            // Refuse rather than keep walking: the input is attacker-influenced and the only
            // reason to continue would be to report a number nobody needs.
            return Err(ActChainError::MalformedChain);
        }
        match object.get("act") {
            None => return Ok(depth),
            Some(nested) => current = nested,
        }
    }
}

/// The actors in a chain, most recent FIRST.
///
/// For introspection and audit, which issue #125 requires the actor to be visible in. Returning
/// the order the chain means, rather than the order a naive recursive walk happens to produce,
/// so a caller rendering it cannot get the attribution backwards.
///
/// # Errors
///
/// [`ActChainError::MalformedChain`] on the same conditions as [`chain_depth`].
pub fn chain_actors(chain: &Value) -> Result<Vec<String>, ActChainError> {
    // Validates depth and shape first, so the walk below cannot run away on hostile input.
    chain_depth(chain)?;
    let mut actors = Vec::new();
    let mut current = chain;
    while let Some(object) = current.as_object() {
        if let Some(subject) = object.get("sub").and_then(Value::as_str) {
            actors.push(subject.to_owned());
        }
        match object.get("act") {
            None => break,
            Some(nested) => current = nested,
        }
    }
    Ok(actors)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ActChainError, MAX_ACT_DEPTH, chain_actors, chain_depth, extend_act_chain};

    #[test]
    fn the_first_hop_produces_a_single_link() {
        let chain = extend_act_chain(None, "svc-a").expect("extended");
        assert_eq!(chain, json!({"sub": "svc-a"}));
        assert_eq!(chain_depth(&chain).expect("depth"), 1);
    }

    /// THE ordering property: the most recent actor is OUTERMOST.
    ///
    /// Inverting this does not produce an obviously broken token. It produces a well-formed one
    /// naming the wrong party as the current actor, so an audit trail reads backwards and an
    /// authorization decision on "the immediate actor" picks the party furthest from the
    /// request.
    #[test]
    fn the_most_recent_actor_is_outermost() {
        let first = extend_act_chain(None, "svc-a").expect("extended");
        let second = extend_act_chain(Some(&first), "svc-b").expect("extended");
        assert_eq!(
            second,
            json!({"sub": "svc-b", "act": {"sub": "svc-a"}}),
            "svc-b acted most recently, so it must be the outer link"
        );
        assert_eq!(
            chain_actors(&second).expect("actors"),
            vec!["svc-b".to_owned(), "svc-a".to_owned()],
            "most recent first"
        );
    }

    #[test]
    fn a_three_hop_chain_nests_in_order() {
        let a = extend_act_chain(None, "svc-a").expect("a");
        let b = extend_act_chain(Some(&a), "svc-b").expect("b");
        let c = extend_act_chain(Some(&b), "svc-c").expect("c");
        assert_eq!(
            c,
            json!({"sub": "svc-c", "act": {"sub": "svc-b", "act": {"sub": "svc-a"}}})
        );
        assert_eq!(chain_depth(&c).expect("depth"), 3);
        assert_eq!(
            chain_actors(&c).expect("actors"),
            vec!["svc-c", "svc-b", "svc-a"]
        );
    }

    /// The cap refuses the hop that would exceed it, while the responsible party is still
    /// visible, rather than letting a token grow until something downstream rejects it far from
    /// the cause.
    #[test]
    fn the_chain_is_capped_at_the_configured_depth() {
        let mut chain = extend_act_chain(None, "svc-0").expect("first");
        for hop in 1..MAX_ACT_DEPTH {
            chain = extend_act_chain(Some(&chain), &format!("svc-{hop}")).expect("hop");
        }
        assert_eq!(chain_depth(&chain).expect("depth"), MAX_ACT_DEPTH);
        assert_eq!(
            extend_act_chain(Some(&chain), "one-too-many").unwrap_err(),
            ActChainError::TooDeep,
        );
    }

    /// An empty actor would produce a link identifying nobody, which is worse than no link: the
    /// token would claim a delegation happened and name no party.
    #[test]
    fn an_empty_actor_is_refused() {
        for actor in ["", "   ", "\t"] {
            assert_eq!(
                extend_act_chain(None, actor).unwrap_err(),
                ActChainError::EmptyActor,
                "{actor:?} must be refused"
            );
        }
    }

    #[test]
    fn a_malformed_chain_is_refused_rather_than_extended() {
        for bad in [
            json!("not-an-object"),
            json!([{"sub": "svc-a"}]),
            json!({}),
            json!({"sub": ""}),
            json!({"sub": 42}),
            json!({"sub": "svc-a", "act": "not-an-object"}),
        ] {
            assert_eq!(
                chain_depth(&bad).unwrap_err(),
                ActChainError::MalformedChain,
                "{bad} must be refused"
            );
            assert_eq!(
                extend_act_chain(Some(&bad), "svc-b").unwrap_err(),
                ActChainError::MalformedChain,
                "{bad} must not be extended"
            );
        }
    }

    /// A chain that arrives ALREADY over-deep is refused rather than walked.
    ///
    /// The input is attacker-influenced: continuing would mean walking whatever depth was
    /// supplied to report a number nobody needs.
    #[test]
    fn an_over_deep_incoming_chain_is_refused_without_walking_it() {
        let mut chain = json!({"sub": "svc-0"});
        for hop in 1..(MAX_ACT_DEPTH + 5) {
            chain = json!({"sub": format!("svc-{hop}"), "act": chain});
        }
        assert_eq!(
            chain_depth(&chain).unwrap_err(),
            ActChainError::MalformedChain
        );
        assert_eq!(
            chain_actors(&chain).unwrap_err(),
            ActChainError::MalformedChain
        );
    }

    /// `chain_actors` validates before walking, so it cannot run away on hostile input even
    /// though its own loop has no counter.
    #[test]
    fn listing_actors_validates_before_walking() {
        let bad = json!({"sub": "svc-a", "act": {"no-sub": true}});
        assert_eq!(
            chain_actors(&bad).unwrap_err(),
            ActChainError::MalformedChain
        );
    }

    /// Extending is deterministic: the same inputs give the same chain, so a retried exchange
    /// cannot produce a differently-shaped token.
    #[test]
    fn extending_is_deterministic() {
        let base = extend_act_chain(None, "svc-a").expect("a");
        let first = extend_act_chain(Some(&base), "svc-b").expect("b");
        let second = extend_act_chain(Some(&base), "svc-b").expect("b again");
        assert_eq!(first, second);
    }

    #[test]
    fn every_error_describes_itself_distinctly() {
        let all = [
            ActChainError::TooDeep,
            ActChainError::EmptyActor,
            ActChainError::MalformedChain,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in all {
            assert!(error.as_str().len() > 20);
            assert!(seen.insert(error.as_str()), "{error:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }

    /// The chain a caller builds round-trips through the readers, so what is written is what
    /// introspection reports.
    #[test]
    fn a_built_chain_round_trips_through_the_readers() {
        let mut chain: Value = extend_act_chain(None, "svc-0").expect("first");
        let mut expected = vec!["svc-0".to_owned()];
        for hop in 1..MAX_ACT_DEPTH {
            let name = format!("svc-{hop}");
            chain = extend_act_chain(Some(&chain), &name).expect("hop");
            expected.insert(0, name);
        }
        assert_eq!(chain_actors(&chain).expect("actors"), expected);
        assert_eq!(chain_depth(&chain).expect("depth"), expected.len());
    }
}
