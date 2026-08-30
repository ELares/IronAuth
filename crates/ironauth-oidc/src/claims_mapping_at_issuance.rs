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
    /// The rules were read but refused.
    ///
    /// Distinct from [`Self::Unreadable`] because the two point at different operators. An
    /// unreadable document is one nobody can parse, which is a version or a row to check.
    ///
    /// A REFUSAL IS NOW TWO THINGS, and this doc used to name only the first. Most refusals
    /// mean a document the admin path should never have accepted -- one writing a protected
    /// claim -- which is a fence to check. A `cel` rule can also fail at EVALUATION, on an
    /// input larger than it declared, and that one the write fence CANNOT see: it depends on
    /// the claim set of the login in front of you. The logged refusal names which.
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

/// Read this client's mapping and apply it to `source`, projecting onto `destination`.
///
/// PRIVATE, and the two-token `resolve` wrapper that used to sit above it is deleted.
/// Neither had a caller outside this module: every door goes through
/// [`apply_to_with_hook`] or [`apply_to_machine_token`], which is what those two are for.
/// A public resolver is how the next door quietly picks the wrong `Destination` for the
/// mint it is doing -- and the reason given for keeping `resolve` public, "the two
/// ID-token-only doors read it", was false. They read `apply_to_with_hook` like the rest.
///
/// # The three doors this does not reach DIRECTLY, and where they went
///
/// `client_credentials.rs`, `jwt_bearer.rs` and `token_exchange.rs` build a
/// `ClientCredentialsMintRequest`, so they call [`apply_to_machine_token`] rather than this
/// function. They are no longer unreached: `custom_claims` is now a [`MappedAccessClaims`] and
/// all three resolve a mapping and run a hook.
///
/// The paragraphs below are kept because they record WHY it took a criterion audit to notice,
/// and the reasoning is still the reasoning. What has changed is only the last line of it.
///
/// "A machine token has no user claims" was the reason given, and it is right only for
/// `client_credentials`. A token-exchange token carries the SUBJECT's subject and a JWT-bearer
/// token carries a mapped federated principal; both are tokens about a person. The correct
/// reason is narrower: those paths carry no user extra-claims bag to map, so reaching them means
/// deciding what a mapping's SOURCE is on a grant that resolves no claims -- a question about
/// those grants rather than about this seam. Issue #113 names both as first-class for the
/// uniform contract, so it is work, not a decision already made.
///
/// It is now done. The source is the client's static bag for `client_credentials` and an empty
/// document for the other two, and [`apply_to_machine_token`] says why those two differ.
///
///
/// # Errors
///
/// [`MappingFault`] when the store cannot answer or the stored document cannot be read or
/// applied. Every one fails the issuance; see the module header for why.
async fn resolve_for(
    store: &Store,
    scope: Scope,
    client_id: &str,
    source: &BTreeMap<String, serde_json::Value>,
    destination: claims_mapping::Destination,
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

    claims_mapping::apply_for(&rules, source, destination)
        .map(Resolved::Mapped)
        .map_err(|refusal| {
            tracing::error!(
                target: "ironauth.claims_mapping",
                tenant = %scope.tenant(),
                client_id,
                %refusal,
                // The REFUSAL says which, and this line no longer guesses. It read "a stored
                // claim mapping writes a protected claim", which was every case until a `cel`
                // rule could fail at EVALUATION -- a refusal the write fence is documented as
                // unable to see. Telling an operator to audit claim names for an oversized
                // input sends them to the wrong place, and `%refusal` already carries the
                // rule index and the reason.
                "a stored claim mapping was refused; refusing the issuance"
            );
            MappingFault::Refused
        })
}

/// Turn a [`serde_json::Map`] into the shape [`claims_mapping::apply_for`] takes.
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

/// WHERE the issuance is running: the store, the environment, and the hook runtime if one is
/// configured.
///
/// A struct rather than three more parameters, and the arity lint is the symptom rather than
/// the reason. These three are the only arguments that do NOT vary per issuance -- every door
/// reads all three off the same `state` -- while `scope`, `client_id`, `grant_type`, `subject`
/// and the claim maps are the event. Separating them means a door cannot pass one issuance's
/// store with another's runtime, and it is the same argument `Invocation`'s own doc makes one
/// layer down: two `&str` parameters in a row compile when swapped, and so do two `&Store`s.
///
/// `env` is here because the hook path AUDITS (issue #113 criterion 5): a claim the fence
/// refuses is written to the audit stream, and every audited write in this codebase takes the
/// environment that stamps it. Before that this seam needed no clock and no id, which is why
/// it had neither.
#[derive(Clone, Copy)]
pub struct Issuance<'a> {
    /// The store the mint reads its mapping and hook from, and writes the refusal audit to.
    pub store: &'a Store,
    /// The environment that stamps the audit row: its clock and its id generator.
    pub env: &'a ironauth_env::Env,
    /// The WASM hook runtime, absent when the server is built or configured without hooks.
    pub runtime: Option<&'a std::sync::Arc<crate::token_hook::HookRuntime>>,
}

impl<'a> Issuance<'a> {
    /// Read all three off the server state, which is where every door has them.
    ///
    /// A constructor rather than a struct literal at each of the eight doors, for the reason
    /// the struct exists at all: three fields spelled out eight times is eight places to get
    /// one of them wrong, and the one that would be silent is `runtime` -- a door passing
    /// `None` there does not fail to compile, it issues a token the operator's hook never
    /// shaped. Review has already measured that exact defect on this seam once.
    #[must_use]
    pub fn for_state(state: &'a crate::state::OidcState) -> Self {
        Self {
            store: state.store(),
            env: state.env(),
            runtime: state.hook_engine(),
        }
    }
}

/// Resolve and apply this client's mapping, then run its deployed WASM hook (issue #114).
///
/// The one entry point every mint site calls. A thin `apply_to`, WITHOUT the hook parameters,
/// existed for one commit and is gone: once every door passed an engine it had zero callers,
/// and a public function nothing calls is the shape that lets the next door quietly use the
/// weaker one. (That old name is the one in the paragraph above; a blanket rename put the NEW
/// name into a sentence whose whole subject was the old one, and the result read as a function
/// describing its own deletion.)
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
/// [`MappingFault`] from the mapping half always, and from the hook half only when the client's
/// policy is `fail_closed` -- which is the default. Under `fail_open` a hook fault returns
/// `Ok` with the hook's contribution simply absent.
///
/// So a successful return is NOT evidence the hook ran, and that matters more than it sounds:
/// a hook's answer REPLACES the claim set, so one deployed to STRIP a claim, failing open,
/// yields a token that still carries it. See `token_hook`'s header for why fail-closed is the
/// default and what opting out means.
///
/// This contract said hook faults refuse unconditionally through the change that made them
/// configurable. It is the seam every mint door reads, which is why the staleness is recorded
/// rather than quietly overwritten.
pub async fn apply_to_with_hook(
    issuance: Issuance<'_>,
    scope: Scope,
    client_id: &str,
    grant_type: &str,
    subject: Option<&str>,
    extra_claims: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<MappedAccessClaims, MappingFault> {
    let Issuance {
        store,
        env,
        runtime,
    } = issuance;
    let source = as_source(extra_claims);
    let mut access = match resolve_for(
        store,
        scope,
        client_id,
        &source,
        // TWO tokens: this seam rewrites `extra_claims` into the ID-token set and returns the
        // access-token set, so placement means what it says.
        claims_mapping::Destination::TwoTokens,
    )
    .await?
    {
        // Untouched. NOT "an empty mapping applied": a client with no mapping issues exactly
        // what it issued before this seam existed, and the two cases produce opposite results
        // for the same input.
        Resolved::NoMapping => serde_json::Map::new(),
        Resolved::Mapped(mapped) => {
            *extra_claims = as_claims(mapped.id_token);
            as_claims(mapped.access_token)
        }
    };

    let Some(runtime) = runtime else {
        return Ok(MappedAccessClaims(access));
    };

    // Without the `wasm-hooks` feature `HookRuntime` is uninhabited, so `runtime` cannot be
    // `Some` and the block below is unreachable -- proved by the compiler rather than asserted.
    #[cfg(not(feature = "wasm-hooks"))]
    {
        // Named so this build does not warn them unused. They are read by the block below,
        // which this build does not compile; underscore-prefixing the PARAMETERS instead would
        // silence the warning in the build that does compile it, which is the build where an
        // unused hook input would be a real defect worth hearing about.
        let _ = (env, grant_type, subject, &mut access);
        runtime.unreachable()
    }

    #[cfg(feature = "wasm-hooks")]
    {
        let contributed = crate::token_hook::run(
            store,
            env,
            runtime,
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
            // Folded onto ONE fault type, because every caller does the same thing with both
            // and a second variant it never distinguishes is a distinction that exists only in
            // the type. The hook's own reason is already logged where it happened, with the
            // client and the bound it hit -- which is what an operator needs and what a client
            // must not learn.
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
            // THE HOOK'S ANSWER REPLACES the set, it does not merge into it. That is what the
            // WIT contract means -- a hook receives both claim lists and returns both, and the
            // shipped `good` guest echoes its input plus one addition precisely because echoing
            // is how you keep a claim under a replace contract.
            //
            // The first version merged, and review caught what that costs: a hook deployed to
            // STRIP a claim, by returning everything except `email`, produced a token that
            // still carried it. Silently. And the fail-closed argument this module and its
            // callers all rest on -- "a hook can REMOVE a claim as easily as add one, so
            // ignoring one that failed issues more than the operator deployed" -- was false of
            // the dispatch that stated it.
            //
            // Everything the hook returned has already been through `filter_hook_claims`, so a
            // replace cannot smuggle a protected name in. What it CAN do is drop one the mint
            // put there, which is the point: the mint rebuilds its own protocol claims after
            // this, so what a hook can drop is exactly the enriched and mapped set it was
            // handed.
            *extra_claims = contributed.id_token.into_iter().collect();
            access = contributed.access_token.into_iter().collect();
        }
        Ok(MappedAccessClaims(access))
    }
}

/// Whether a grant MINTS AN ID TOKEN, and so whether a hook's ID-token half can reach one.
///
/// The three grants that answer `false` are exactly the callers of [`apply_to_machine_token`],
/// which hands the guest an EMPTY ID-token list and DROPS the one it returns. A caller running
/// the dispatch OUTSIDE an issuance -- the admin draft-test endpoint, issue #114 criterion 5 --
/// has to know that, or it runs the hook on an input no login on that grant produces and
/// reports an ID half no token on that grant can carry.
///
/// Keyed on `registry::GrantType`, not on three string literals: the doors pass the registry's
/// own wire value for exactly this reason, and a second copy of these names is how the two
/// drift. The `debug_assert!` at the top of [`apply_to_machine_token`] is what holds them
/// together -- a fourth machine door added without teaching this function fails the suite
/// rather than shipping a draft report that disagrees with its own issuance.
#[must_use]
pub fn grant_mints_id_token(grant_type: &str) -> bool {
    grant_type != crate::registry::GrantType::ClientCredentials.as_str()
        && grant_type != crate::registry::GrantType::JwtBearer.as_str()
        && grant_type != crate::registry::GrantType::TokenExchange.as_str()
}

/// Resolve and run the same mapping and hook for a token that has NO ID token.
///
/// `client_credentials`, `jwt:bearer` and token exchange mint one access token and nothing else,
/// so they build a `ClientCredentialsMintRequest`. Before this existed they reached NEITHER the
/// mapping NOR the hook, and issue #113 names that exact shape as the thing to avoid:
///
/// > Auth0 covers machine-to-machine only through a separate credentials-exchange hook, an
/// > inconsistency to avoid.
///
/// We had the inconsistency by accident. `MintRequest::access_extra_claims` is fenced by
/// [`MappedAccessClaims`], and that fence is a field on ONE struct: the three doors that build
/// the other struct were never in a position to be asked. See that type's header.
///
/// # ONE TOKEN, top to bottom, and the first version of this was a union
///
/// The first version delegated to [`apply_to_with_hook`] and merged the two halves it returned.
/// That was wrong in two measured ways, and both are the same mistake: taking a two-token answer
/// and inventing a projection after the information needed to project it is gone.
///
/// **It inverted `place: id_token`.** That rule means "keep this claim away from the resource
/// servers in `aud`", and it is the DEFAULT for an unplaced claim only because reaching an
/// access token has to be asked for -- see `claims_mapping::apply_for`, which records the
/// disclosure this prevented. Folding the ID half into the access token put an
/// explicitly-excluded claim into the one token the rule exists to keep it out of. Now the
/// projection happens in `apply_for`, where "the operator placed this" and "nothing placed
/// this" are still distinguishable: unplaced lands in the one token, `id_token` is not emitted.
///
/// **It deleted the client's static claims the day a hook was deployed.** The union handed the
/// static blob to the guest as `id_token_claims`, for a token with no ID token. The WIT contract
/// is a REPLACE, so a hook author who filled `access_token_claims` and left the other list
/// empty -- the natural thing to write for a machine grant -- silently emptied every static
/// claim. Review measured it: `department` present before the hook, absent after a guest that
/// does nothing but echo. Now the guest is handed the claims where they actually live, as
/// `access_token_claims`, and an EMPTY id list.
///
/// The hook's `id_token_claims` response is DISCARDED here, because there is no ID token to put
/// it in. That also restores the contribution cap: `filter_hook_claims` bounds a hook at 32
/// claims per token, and fencing two halves into one token made it 64 on exactly the grants
/// whose mint runs no size budget.
///
/// # What is NOT withheld, and what is
///
/// The client's declarative MAPPING runs on all three, including the two whose token speaks for
/// somebody else. That is consistent with every other grant: a client's mapping already shapes
/// the tokens it causes to be minted for interactive users, and a `static` rule reaching an
/// exchanged token is the same power, not a new one. `the_mapping_reaches_an_exchanged_token`
/// pins it so it is a decision rather than an accident.
///
/// What stays withheld from a delegated token is `clients.custom_token_claims`, and the reason
/// is narrower than "config must not decorate another subject": those claims describe the
/// client's own SERVICE ACCOUNT, so putting them on a token that speaks for a user conflates two
/// identities. A mapping is a token-shaping facility; that blob is an identity's attributes.
/// `token_exchange.rs` and `jwt_bearer.rs` pass an empty source for that reason.
///
/// # Errors
///
/// [`MappingFault`], as [`apply_to_with_hook`]. Note that all three doors gained failure modes
/// they did not have: a `claims_mappings` read now happens on every issuance and a store error
/// fails it closed. For `client_credentials` that sits directly beside `load_custom_claims`,
/// which is deliberately fail-OPEN, and the two now disagree by design: a malformed static blob
/// under-claims, while shaping that did not run means an entitlement the operator meant to
/// REMOVE is still in the token.
pub async fn apply_to_machine_token(
    issuance: Issuance<'_>,
    scope: Scope,
    client_id: &str,
    grant_type: &str,
    subject: Option<&str>,
    static_claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<MappedAccessClaims, MappingFault> {
    // THE PREDICATE AND THE DOORS AGREE, and this is what says so. Every caller of this
    // function is a grant that mints no ID token; `grant_mints_id_token` names that set for the
    // draft endpoint, which cannot call this function and has to ask.
    debug_assert!(
        !grant_mints_id_token(grant_type),
        "a grant reaching apply_to_machine_token mints no ID token, so grant_mints_id_token \
         must agree: {grant_type}"
    );
    let Issuance {
        store,
        env,
        runtime,
    } = issuance;
    let source = as_source(static_claims);
    let mut single = match resolve_for(
        store,
        scope,
        client_id,
        &source,
        claims_mapping::Destination::OneAccessToken,
    )
    .await?
    {
        // Untouched, which is what these three doors issued before this seam existed.
        Resolved::NoMapping => static_claims.clone(),
        Resolved::Mapped(mapped) => as_claims(mapped.access_token),
    };

    let Some(runtime) = runtime else {
        return Ok(MappedAccessClaims(single));
    };

    #[cfg(not(feature = "wasm-hooks"))]
    {
        let _ = (env, grant_type, subject, &mut single);
        runtime.unreachable()
    }

    #[cfg(feature = "wasm-hooks")]
    {
        // EMPTY, and that is the contract for a grant with no ID token: there is no list of
        // ID-token claims because there is no ID token.
        let no_id_token = serde_json::Map::new();
        let contributed = crate::token_hook::run(
            store,
            env,
            runtime,
            &crate::token_hook::Invocation {
                scope,
                client_id,
                grant_type,
                subject,
                id_token_claims: &no_id_token,
                access_token_claims: &single,
            },
        )
        .await
        .map_err(|fault| {
            tracing::error!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                client_id,
                grant_type,
                ?fault,
                "refusing the issuance because the client's hook did not complete"
            );
            MappingFault::Refused
        })?;

        if let Some(contributed) = contributed {
            // REPLACE, as everywhere else. `contributed.id_token` is dropped: a hook that fills
            // it on a machine grant is answering a question nobody asked, and there is nowhere
            // to put it. Dropping rather than erroring because the shipped `echo-request`
            // fixture fills it, and because a hook written once for every grant is the point of
            // the uniform contract.
            //
            // LOGGED, though. Every other discard in this family says what it refused and why,
            // and a hook author whose ID-token claims vanish with no line anywhere has no way
            // to learn that this grant has no ID token. Only when there is something to say:
            // the common case is an empty list and a silent one.
            if !contributed.id_token.is_empty() {
                tracing::info!(
                    target: "ironauth.hooks",
                    tenant = %scope.tenant(),
                    client_id,
                    grant_type,
                    discarded = contributed.id_token.len(),
                    "the hook returned ID-token claims on a grant that mints no ID token; they \
                     are dropped, and the access-token claims it returned were kept"
                );
            }
            single = contributed.access_token.into_iter().collect();
        }
        Ok(MappedAccessClaims(single))
    }
}

/// The access-token claims a mapping produced, in a wrapper only this module can build.
///
/// TWO fields take one of these -- `MintRequest::access_extra_claims` and
/// `ClientCredentialsMintRequest::custom_claims` -- so a door that mints a token for a client
/// CANNOT do it without calling [`apply_to_with_hook`] or [`apply_to_machine_token`]. Neither
/// field has another source. That is the point, and it is a repair rather than a flourish.
///
/// It was one field until issue #113's criterion-1 audit, and that is exactly how three grants
/// came to mint tokens that ran no mapping and no hook: a fence is a property of a FIELD, and
/// those doors filled in a different one.
///
/// # WHAT THIS FENCE DOES NOT PROVE
///
/// That the door ran the HOOK. It proves the door resolved the MAPPING, which is a different
/// claim, because `runtime` is an ordinary parameter and `None` is a legitimate value for it --
/// it is how a deployment with hooks disabled issues tokens. A door that hard-codes `None`
/// instead of passing `state.hook_engine()` produces a perfectly well-typed
/// `MappedAccessClaims` and no test fails.
///
/// So each door needs its own test, and each of those needs to be confirmed against exactly
/// that mutation. There are NINE production doors that mint a CLAIM-BEARING token --
/// `authorize`, `ciba_grant`, `client_credentials`, `device`, `fedcm`, `jwt_bearer`,
/// `token_exchange`, and two in `token` -- and eight of the nine are covered.
///
/// "Every caller of `tokens::mint*`" is NOT the rule that produces those nine, and saying so
/// would be a derivation that does not derive its own number: there are twelve such callers,
/// and three of them are `mint_refresh_token`, which mints an opaque handle with no claims in
/// it for a mapping or a hook to shape. The rule is the claim-bearing mint, and the table is:
///
/// | Door | Test |
/// | --- | --- |
/// | authorization code | `a_deployed_hook_customizes_a_real_access_token` |
/// | refresh | `the_refresh_grant_runs_the_hook` |
/// | device | `the_device_grant_runs_the_hook` |
/// | implicit / front channel | `the_front_channel_authorize_door_runs_the_hook` |
/// | CIBA | `the_ciba_grant_runs_the_hook` |
/// | `client_credentials` | `the_client_credentials_grant_runs_the_hook` |
/// | `jwt:bearer` | `the_jwt_bearer_grant_runs_the_hook` |
/// | token exchange | `the_token_exchange_grant_runs_the_hook` |
///
/// The first two rows are ONE call site, `token.rs`'s `apply_claims_mapping`, so the table's
/// per-row independence is real for the other six and not for those. Mutating that single line
/// takes down ten tests at once, which is coverage but not per-door coverage: what distinguishes
/// the two rows is the grant string each asserts, not a separate wiring. Row 1 is also served by
/// a second test, `the_code_exchange_tells_the_hook_which_grant_it_is`, which is the one that
/// reads that string back; the exit-criterion test named in the table proves a hook shaped a
/// real token and says nothing about the payload.
///
/// **FEDCM IS NOT.** `fedcm.rs` passes `state.hook_engine()` and nothing measures that it does.
/// No test in the suite drives the id-assertion endpoint to a minted token -- the flow needs
/// the `Sec-Fetch-Dest: webidentity` posture, an account selection and RP metadata that no
/// fixture builds today -- so writing that driver is its own piece of work rather than a line
/// in this one. It is the last unmeasured door and it is named here so it stays visible.
///
/// The measurement below was made against the mapping when this function was called `apply_to`,
/// and it is about the mapping. The rename carried the sentence onto the hook, where it was
/// never true.
///
/// Review measured the alternative, BEFORE any of those tests existed: with the field taking a
/// plain map, emptying the mapping call at the FedCM, CIBA and front-channel-authorize doors
/// each left the whole suite green,
/// because those three are driven by no test that installs a mapping. A structural argument
/// ("they all call the same function") is not a measurement, and structure cannot express
/// reachability. Now the compiler asks the question at every door, including doors nobody has
/// written yet.
///
/// The wrapped map may be empty. That is `NoMapping`, and it is the common case: a client with
/// no mapping contributes no access-token claims and issues exactly what it did before.
// NO `Default`. The derive was a PUBLIC associated function, so any code in any crate could
// build this without resolving a mapping at all -- which is the entire fence, and the comments above
// claimed it held. Measured: replacing the FedCM door's resolver call with
// `MappedAccessClaims::default()` compiled clean with zero clippy warnings. A newtype whose
// bypass is one derive away is not a fence, and the derive was the one thing nobody grepped for
// while a `none_for_a_clientless_mint` constructor was advertised as the only hatch. That
// constructor is gone too: review found it had ZERO callers repo-wide while remaining a public
// way to build this type without resolving anything, which is a bypass kept open for nobody.
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
}
