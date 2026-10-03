// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management operations that name their organization in the REQUEST BODY.
//!
//! # Why this exists at all
//!
//! Three independent sweeps decide which operations they are about by asking the same
//! question of the committed contract: does the documented path contain
//! `organizations/{organization_id}`. `org_confinement_surface.rs` uses it to decide which
//! handlers must reach the delegated-administration fence, `org_audit_attribution.rs` to
//! decide which writes must name their organization on the audit row, and
//! `deleted_environment.rs` to decide which operations its coverage sweep must drive.
//!
//! That question was ALREADY WRONG when it was written, and `createPortalLink` is simply where
//! somebody noticed. `createLogStream` had been taking its organization as a body field since
//! the log-stream slice shipped, and all three sweeps had been agreeing it was not an
//! organization operation the whole time -- leaving it out of their DENOMINATOR while reporting
//! full coverage. The blind spot did not arrive with this PR; a second instance of it did, and
//! that instance was the one that got looked at.
//!
//! Both were real bypasses. A management credential confined to one organization could mint a
//! portal link granting configuration authority over a sibling, and could point a log stream at
//! a sibling's audit rows. The second had shipped.
//!
//! An earlier version of this paragraph said the question had been answered correctly until
//! `createPortalLink` arrived. It is corrected here rather than quietly rewritten, because the
//! wrong version dated a shipped exposure to an unmerged branch.
//!
//! # Why it is DERIVED and not a list somebody maintains
//!
//! The first repair was a hand-written list of operation ids, and it was the wrong shape. It
//! closed the hole for the one operation somebody had already found, and left the CLASS
//! exactly as open as before: a second body-addressed write added tomorrow is invisible to all
//! three sweeps in precisely the way `createPortalLink` was, because every sweep filters on
//! list membership. A list is a record of what somebody noticed. The defect is not noticing.
//!
//! So membership is computed from the document instead. An operation is body-addressed when
//! its request schema carries an `organization_id` property and its path does not already
//! name one. Nobody has to remember; a new endpoint of this shape joins the denominator on
//! the run after it is documented.
//!
//! THAT CHANGE PAID FOR ITSELF ON THE FIRST RUN. The derivation named `createLogStream`, which
//! nobody had looked at: it took `organization_id` from its body and passed it straight to the
//! store with no fence at all, and that column decides which organization's rows the shipper
//! reads. A credential confined to organization A could point a stream at organization B and
//! ship B's audit and authentication events to a sink of its choosing.
//!
//! # What a reader must not conclude
//!
//! Being in this set does not make an operation safe; it makes it VISIBLE to the checks that
//! decide whether it is. Each sweep still finds its own evidence -- the fence call, the
//! attribution call, a driving case -- and each fails on a member it cannot find that evidence
//! for.
#![allow(dead_code)]

use std::collections::BTreeSet;

/// The committed management contract, read by every sweep that calls in here.
const COMMITTED_SPEC: &str = include_str!("../../../../docs/openapi/management.json");

/// Operations whose organization arrives in the request body rather than the path.
///
/// # What the shape of the answer rests on
///
/// A request schema reaches this through a `$ref` into `components/schemas`, which is how
/// utoipa emits every body in this document; an inline schema is read directly so a future
/// generator change does not silently empty the set. Both are resolved, and an operation
/// whose path ALREADY names an organization is excluded -- it is path-addressed, the sweeps
/// find it by the prefix, and returning it here would double-count it.
///
/// # The anti-vacuity check is the point
///
/// A derivation that silently returns nothing is worse than the hand-written list it
/// replaced: every sweep would go back to reporting full coverage of a set with a hole in it,
/// and nothing would say so. So this refuses to answer an empty set. The two members are real
/// and both are in the shipped contract; if a future document change makes this empty, the
/// question to ask is whether the generator's shape changed, not whether the product stopped
/// having body-addressed writes.
#[must_use]
pub fn body_addressed_operations() -> BTreeSet<String> {
    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let schemas = &doc["components"]["schemas"];
    let mut found = BTreeSet::new();

    for (template, item) in doc["paths"].as_object().expect("paths") {
        if template.contains("organizations/{organization_id}") {
            continue;
        }
        for operation in item.as_object().expect("operations").values() {
            let bodies = &operation["requestBody"]["content"];
            let carries = bodies
                .as_object()
                .into_iter()
                .flatten()
                .any(|(_media_type, body)| carries_organization(&body["schema"], schemas, 0));
            if carries && let Some(id) = operation["operationId"].as_str() {
                found.insert(id.to_owned());
            }
        }
    }

    assert!(
        !found.is_empty(),
        "the body-addressed derivation found NOTHING, so every sweep that reads it has \
         quietly gone back to covering only path-addressed operations. That is the exact \
         blind spot this module exists to close, and an empty answer hides it again. The \
         likely cause is a change in how request bodies are emitted into the document, not \
         the product having stopped taking organizations in request bodies."
    );
    found
}

/// Whether `schema` carries an `organization_id` property, following refs and composition.
///
/// # Why it is not a single lookup for `properties/organization_id`
///
/// The first version was, and it recognised exactly the shape utoipa happens to emit for a
/// struct with a plain field. That is not the only shape it emits. A body assembled from a
/// shared struct with `#[serde(flatten)]` becomes an `allOf`, which has no top-level
/// `properties` at all, so the operation would be silently absent from every sweep -- the
/// original defect, reintroduced by the mechanism built to prevent it. The whole point of
/// deriving membership was to stop depending on somebody noticing, and a derivation that only
/// recognises the shapes its author happened to see is the same dependency wearing a
/// different hat.
///
/// So it follows `$ref`, descends `allOf`/`anyOf`/`oneOf`, and reads `properties`. It does NOT
/// descend into a nested object's own properties: an `organization_id` one level down inside
/// some unrelated sub-object is a different field, not this operation's organization.
///
/// THE DEPTH BOUND IS AGAINST A CYCLE, not against deep documents. A `$ref` that points at an
/// ancestor is legal JSON Schema and would recurse forever; eight levels is far past anything
/// utoipa emits.
fn carries_organization(
    schema: &serde_json::Value,
    schemas: &serde_json::Value,
    depth: u8,
) -> bool {
    if depth > 8 {
        return false;
    }
    if let Some(reference) = schema["$ref"].as_str() {
        let name = reference.rsplit('/').next().unwrap_or_default();
        return carries_organization(&schemas[name], schemas, depth + 1);
    }
    if schema["properties"]["organization_id"].is_object() {
        return true;
    }
    ["allOf", "anyOf", "oneOf"].iter().any(|key| {
        schema[key]
            .as_array()
            .into_iter()
            .flatten()
            .any(|branch| carries_organization(branch, schemas, depth + 1))
    })
}
