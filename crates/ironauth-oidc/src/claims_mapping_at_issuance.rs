// SPDX-License-Identifier: MIT OR Apache-2.0
//! Applying a stored declarative claim mapping when a token is minted (issue #113 criterion 4).
//!
//! `claims_mapping` defines and applies the rules; `claims_mappings` stores them; a config
//! snapshot EXPORTS them. This is the seam that made any of it reach a token. Before it the
//! rules had ZERO production callers of any kind -- not one, as an earlier version of this
//! paragraph said -- so a mapping an operator configured and saw in a snapshot export changed
//! nothing about any token ever issued.
//!
//! Two things that paragraph also got wrong, corrected here because they are the kind of claim
//! a reader budgets against:
//!
//! - **Promotion does not carry a mapping yet.** `promotion.rs` leaves `claims_mapping` empty,
//!   blocked on the same missing primitive as `client` and `signup_form`. Criterion 4 ends with
//!   "and promote via config snapshots"; that half is open.
//! - **The write path validates because a later change made it so**, not because it always did.
//!   When this module first said "the admin path validates before storing", there was no admin
//!   path at all: `claims_mapping::validate` had no production caller, and
//!   `ActingClaimsMappingRepo::set` stored the string verbatim and said so. The fail-closed
//!   decision below rested on a fence that did not exist, and one ordinary write of a rule set
//!   naming `sub` was a per-client login outage. The admin surface is what makes the sentence
//!   true.
//!
//! # Where the claims come from
//!
//! The source is the ID token's extra-claims bag as the token endpoint has assembled it: the
//! `claims` request-parameter members, the scope-derived claims under the non-conform override,
//! and whatever an external policy decision point contributed. Protocol claims are not in it and
//! must not be -- `iss`, `sub`, `aud`, `exp` and `iat` are built by the mint after this runs, and
//! `claims_mapping::validate` refuses a rule that writes one anyway (criterion 5).
//!
//! # A mapping that cannot be read FAILS THE ISSUANCE
//!
//! This is the decision worth defending, because the enrichment bag beside it does the opposite
//! and says so: it is "deliberately fail-OPEN (under-claim rather than fail the login)".
//!
//! A mapping is not an enrichment. It is as likely to REMOVE a claim as to add one --
//! `filter_list` exists so a token does not carry three thousand group names, and `place` exists
//! so a claim stays out of the access token. Treating an unreadable document as "no mapping"
//! would issue the UNFILTERED claim set: MORE than the operator configured, from a rule set
//! nobody could evaluate. Under-claiming is the safe failure for an enrichment; over-claiming is
//! not a safe failure for anything.
//!
//! The document cannot be unreadable by accident ONCE the admin surface is the only writer: it
//! validates before storing, the table constrains the shape, and the snapshot import validates
//! on the way in. A parse failure here then means a downgrade to a version that does not know a
//! rule kind, a hand-edited row, or corruption -- each a reason to stop.
//!
//! That conditional is load bearing and was missing. Fail-closed on a channel anything can write
//! is not a safety property, it is a way to turn one bad write into a per-client login outage.
//! The fence has to exist first.

use std::collections::BTreeMap;

use ironauth_store::{Scope, Store};

use crate::claims_mapping::{self, MappedClaims};

/// Why an issuance could not resolve a mapping.
///
/// Deliberately not carrying the underlying error: the caller turns this into a `server_error`,
/// and the detail belongs in the log rather than in anything a client reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingFault {
    /// The stored document could not be read as a rule set.
    Unreadable,
    /// The rules were read but refused: one writes a protected claim.
    ///
    /// Distinct from [`Self::Unreadable`] because the two point at different operators. A
    /// refusal means a document that the admin path should never have accepted, which is a
    /// fence to check; an unreadable one means a document nobody can parse, which is a version
    /// or a row to check.
    Refused,
    /// The store could not answer.
    Unavailable,
}

/// The claims a mapping produced, or the fact that no mapping is configured.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    /// No mapping exists for this client. The caller issues exactly what it would have before.
    ///
    /// A distinct variant rather than an empty [`MappedClaims`], because the two mean opposite
    /// things: an empty mapping is a rule set that produced no claims and the source must be
    /// DROPPED, while no mapping means the source passes through untouched.
    NoMapping,
    /// A mapping applied, giving the per-token claim sets.
    Mapped(MappedClaims),
}

/// Read this client's mapping and apply it to `source`.
///
/// # The three doors this does NOT reach, and the honest reason
///
/// `client_credentials.rs`, `jwt_bearer.rs` and `token_exchange.rs` build a
/// `ClientCredentialsMintRequest`, which has no extra-claims channel at all -- only
/// `custom_claims`, the per-client static bag from issue #23.
///
/// "A machine token has no user claims" was the reason given, and it is right only for
/// `client_credentials`. A token-exchange token carries the SUBJECT's subject and a JWT-bearer
/// token carries a mapped federated principal; both are tokens about a person. The correct
/// reason is narrower: those paths carry no user extra-claims bag to map, so reaching them means
/// deciding what a mapping's SOURCE is on a grant that resolves no claims -- a question about
/// those grants rather than about this seam. Issue #113 names both as first-class for the
/// uniform contract, so it is work, not a decision already made.
///
/// # Errors
///
/// [`MappingFault`] when the store cannot answer or the stored document cannot be read or
/// applied. Every one fails the issuance; see the module header for why.
pub async fn resolve(
    store: &Store,
    scope: Scope,
    client_id: &str,
    source: &BTreeMap<String, serde_json::Value>,
) -> Result<Resolved, MappingFault> {
    let record = store
        .scoped(scope)
        .claims_mappings()
        .get(client_id)
        .await
        .map_err(|error| {
            tracing::error!(
                target: "ironauth.claims_mapping",
                tenant = %scope.tenant(),
                client_id,
                ?error,
                "a token issuance could not read the client's claim mapping"
            );
            MappingFault::Unavailable
        })?;
    let Some(record) = record else {
        return Ok(Resolved::NoMapping);
    };

    let rules = claims_mapping::parse(&record.rules_json).map_err(|error| {
        tracing::error!(
            target: "ironauth.claims_mapping",
            tenant = %scope.tenant(),
            client_id,
            %error,
            "a stored claim mapping could not be read; refusing the issuance rather than \
             minting a token from a rule set nobody could evaluate"
        );
        MappingFault::Unreadable
    })?;

    claims_mapping::apply(&rules, source)
        .map(Resolved::Mapped)
        .map_err(|refusal| {
            tracing::error!(
                target: "ironauth.claims_mapping",
                tenant = %scope.tenant(),
                client_id,
                %refusal,
                "a stored claim mapping writes a protected claim; refusing the issuance"
            );
            MappingFault::Refused
        })
}

/// Turn a [`serde_json::Map`] into the shape [`claims_mapping::apply`] takes.
///
/// The two are both string-keyed JSON maps and the conversion is mechanical; it lives here so
/// the direction is stated once. `serde_json::Map` is what the token endpoint assembles and what
/// `MintRequest` borrows, and `BTreeMap` is what the mapping layer works in -- the mapping layer
/// is pure and has no reason to depend on `serde_json`'s map type.
#[must_use]
pub fn as_source(
    claims: &serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    claims
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The inverse of [`as_source`].
#[must_use]
pub fn as_claims(
    mapped: BTreeMap<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    mapped.into_iter().collect()
}

/// Resolve and apply this client's mapping, then run its deployed WASM hook (issue #114).
///
/// The one entry point every mint site calls. A thin `apply_to_with_hook` without the hook parameters
/// existed for one commit and is gone: once every door passed an engine it had zero callers,
/// and a public function nothing calls is the shape that lets the next door quietly use the
/// weaker one.
///
/// Rewrites `extra_claims` into the ID-token set and RETURNS the access-token set, because
/// deciding which token a claim goes in is part of what a mapping does (criterion 4:
/// "ID-versus-access-token placement with no custom code").
///
/// THE MAPPING FIRST, THEN THE HOOK, and the order is the decision. The mapping is configuration
/// an operator writes as data; the hook is code. Code should see what configuration produced
/// rather than race it, and an operator debugging a token can read the rules and then read the
/// hook rather than having to hold both in mind at once.
///
/// `engine` absent means hooks are not enabled for this deployment: the mapping applies and
/// `token_hooks` is never read, so a deployment that has not enabled hooks issues exactly what
/// it did before they existed and pays nothing for them.
///
/// # Errors
///
/// [`MappingFault`] from either half. A hook fault is not a separate outcome here because the
/// caller does the same thing with both: refuse the issuance. See `token_hook`'s header for why
/// a hook is fail-CLOSED where the enrichment beside it is fail-open.
pub async fn apply_to_with_hook(
    store: &Store,
    engine: Option<&std::sync::Arc<ironauth_hooks::HookEngine>>,
    scope: Scope,
    client_id: &str,
    grant_type: &str,
    subject: Option<&str>,
    extra_claims: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<MappedAccessClaims, MappingFault> {
    let source = as_source(extra_claims);
    let mut access = match resolve(store, scope, client_id, &source).await? {
        // Untouched. NOT "an empty mapping applied": a client with no mapping issues exactly
        // what it issued before this seam existed, and the two cases produce opposite results
        // for the same input.
        Resolved::NoMapping => serde_json::Map::new(),
        Resolved::Mapped(mapped) => {
            *extra_claims = as_claims(mapped.id_token);
            as_claims(mapped.access_token)
        }
    };

    let Some(engine) = engine else {
        return Ok(MappedAccessClaims(access));
    };

    let contributed = crate::token_hook::run(
        store,
        engine,
        &crate::token_hook::Invocation {
            scope,
            client_id,
            grant_type,
            subject,
            id_token_claims: extra_claims,
            access_token_claims: &access,
        },
    )
    .await
    .map_err(|fault| {
        // Folded onto ONE fault type, because every caller does the same thing with both and a
        // second variant it never distinguishes is a distinction that exists only in the type.
        // The hook's own reason is already logged where it happened, with the client and the
        // bound it hit -- which is what an operator needs and what a client must not learn.
        tracing::error!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            client_id,
            ?fault,
            "refusing the issuance because the client's hook did not complete"
        );
        MappingFault::Refused
    })?;

    if let Some(contributed) = contributed {
        // The hook's claims OVERWRITE the mapping's on a collision, and that is the only order
        // that makes the two composable: an operator who deploys a hook to override something a
        // rule sets has done it deliberately, and the reverse would make the hook silently
        // ineffective on exactly the claims somebody cared enough to write a rule for.
        //
        // Both sides have already been through `filter_hook_claims`, so neither can carry a
        // protected name whichever wins.
        for (name, value) in contributed.id_token {
            extra_claims.insert(name, value);
        }
        for (name, value) in contributed.access_token {
            access.insert(name, value);
        }
    }

    Ok(MappedAccessClaims(access))
}

/// The access-token claims a mapping produced, in a wrapper only this module can build.
///
/// `MintRequest::access_extra_claims` takes one of these, so a door that mints a token for a
/// client CANNOT do it without calling [`apply_to_with_hook`] -- the field has no other source. That is
/// the point, and it is a repair rather than a flourish.
///
/// Review measured the alternative: with the field taking a plain map, emptying the `apply_to_with_hook`
/// call at the FedCM, CIBA and front-channel-authorize doors each left the whole suite green,
/// because those three are driven by no test that installs a mapping. A structural argument
/// ("they all call the same function") is not a measurement, and structure cannot express
/// reachability. Now the compiler asks the question at every door, including doors nobody has
/// written yet.
///
/// The wrapped map may be empty. That is `NoMapping`, and it is the common case: a client with
/// no mapping contributes no access-token claims and issues exactly what it did before.
// NO `Default`. The derive was a PUBLIC associated function, so any code in any crate could
// build this without calling `apply_to_with_hook` -- which is the entire fence, and the comments above
// claimed it held. Measured: replacing the FedCM door's resolver call with
// `MappedAccessClaims::default()` compiled clean with zero clippy warnings. A newtype whose
// bypass is one derive away is not a fence, and the derive was the one thing nobody grepped for
// while `none_for_a_clientless_mint` was advertised as the only hatch.
#[derive(Debug, Clone)]
pub struct MappedAccessClaims(serde_json::Map<String, serde_json::Value>);

impl MappedAccessClaims {
    /// The claims, for the mint to fold.
    #[must_use]
    pub fn as_map(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.0
    }

    /// Build one directly, FOR TESTS ONLY.
    ///
    /// `cfg(test)`-gated so it cannot become the bypass the wrapper exists to prevent: the
    /// mint's own unit tests drive `access_extra_claims` with hand-built bags to exercise the
    /// fold and the budget, which is a different question from whether a door resolved a
    /// mapping, and neither test should need a database to ask it.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(claims: serde_json::Map<String, serde_json::Value>) -> Self {
        Self(claims)
    }

    /// No mapping applied, for a path that mints a token for NO client.
    ///
    /// Deliberately narrow, and deliberately not `Default`-by-accident: the only honest use is a
    /// mint that has no client id to look a mapping up by. A door that HAS one must call
    /// [`apply_to_with_hook`]; reaching for this instead is the bypass the wrapper exists to prevent, and
    /// it is greppable.
    #[must_use]
    pub fn none_for_a_clientless_mint() -> Self {
        Self(serde_json::Map::new())
    }
}
