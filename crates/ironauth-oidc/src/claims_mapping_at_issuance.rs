// SPDX-License-Identifier: MIT OR Apache-2.0
//! Applying a stored declarative claim mapping when a token is minted (issue #113 criterion 4).
//!
//! `claims_mapping` defines and applies the rules; `claims_mappings` stores them; the config
//! snapshot promotes them. This is the seam that made any of it reach a token. Before it, the
//! rules had one production caller (the admin write, which validates) and zero readers, so a
//! mapping an operator configured, promoted from dev to prod, and saw in a snapshot export
//! changed nothing about any token ever issued.
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
//! The document cannot be unreadable by accident: the admin path validates before storing, the
//! table constrains the shape, and the snapshot import validates on the way in. A parse failure
//! here means a downgrade to a version that does not know a rule kind, a hand-edited row, or
//! corruption. Each of those is a reason to stop.

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

/// Resolve and APPLY this client's mapping, in the shape every mint site wants.
///
/// Rewrites `extra_claims` into the ID-token set and returns the access-token set, because
/// deciding which token a claim goes in is part of what a mapping does (criterion 4:
/// "ID-versus-access-token placement with no custom code").
///
/// Every mint site calls THIS rather than [`resolve`], so the two things easy to get wrong are
/// written once: that a client with no mapping passes its claims through untouched rather than
/// having them replaced by an empty set, and that a fault stops the issuance.
///
/// # Errors
///
/// [`MappingFault`], which each caller maps onto its own refusal. There is no fail-open path;
/// see the module header.
pub async fn apply_to(
    store: &Store,
    scope: Scope,
    client_id: &str,
    extra_claims: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, MappingFault> {
    let source = as_source(extra_claims);
    match resolve(store, scope, client_id, &source).await? {
        // Untouched. NOT "an empty mapping applied": a client with no mapping issues exactly
        // what it issued before this seam existed, and the two cases produce opposite results
        // for the same input.
        Resolved::NoMapping => Ok(serde_json::Map::new()),
        Resolved::Mapped(mapped) => {
            *extra_claims = as_claims(mapped.id_token);
            Ok(as_claims(mapped.access_token))
        }
    }
}
