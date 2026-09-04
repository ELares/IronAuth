// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every organization-addressed operation reaches the confinement fence (issue #102,
//! acceptance criterion 2).
//!
//! # Why a structural pin rather than an end-to-end probe per operation
//!
//! Confinement has ONE choke point. `resolve_live_org` performs the existence read and
//! then calls `Principal::require_organization`, which is what answers the uniform
//! not-found for a sibling organization. Every organization-addressed handler routes
//! through it. `delegated_admin.rs` and `delegated_scope_levels.rs` prove the BEHAVIOUR
//! at that choke point end to end; what those cannot prove is that a new endpoint added
//! next year goes through it at all.
//!
//! That is the gap this closes, and it is the gap that matters, because the failure mode
//! is not "the fence is wrong" but "the fence was never reached". This project has
//! shipped that shape repeatedly: a control that exists and a path that does not consult
//! it.
//!
//! # What it can and cannot see, stated because a text scan invites over-reading
//!
//! It is a TEXT scan over the admin sources. It proves each operation's handler, or a
//! helper in the same file that the handler calls, mentions `resolve_live_org`. It cannot
//! prove the call is on every branch, that its result is honoured, or that the right
//! organization is passed. The end-to-end tests own those.
//!
//! It DOES follow one level of same-file delegation, and that is not a refinement: the
//! first version of this scan, without it, reported `disableOrganization` and
//! `enableOrganization` as unfenced. Both are fenced, one frame down, in the
//! `set_organization_state` helper they share. A pin that cried wolf on two of
//! thirty-six would have been turned off rather than fixed.

use std::collections::BTreeSet;

/// Every admin source that declares an organization-addressed operation, plus the modules
/// their handlers delegate into. Read as text so a handler added tomorrow is covered
/// without touching this list, provided its file is here.
const ADMIN_SOURCES: &[(&str, &str)] = &[
    // Added after a review measured the gap: four organization-addressed API-key
    // operations live here and the scan could not see any of them, so the file whose
    // whole purpose is "a new endpoint goes through the fence at all" was blind to a
    // whole module. All four already resolve through `resolve_live_org`; the omission
    // was the scan's, not theirs.
    ("agents.rs", include_str!("../src/agents.rs")),
    // The outbound provisioning module (issue #137): four organization-addressed operations,
    // all four of which resolve through `resolve_live_org`. Added with them rather than after a
    // review measured the gap, which is how `api_keys.rs` got here.
    (
        "scim_push_connections.rs",
        include_str!("../src/scim_push_connections.rs"),
    ),
    ("api_keys.rs", include_str!("../src/api_keys.rs")),
    ("memberships.rs", include_str!("../src/memberships.rs")),
    (
        "org_effective_roles.rs",
        include_str!("../src/org_effective_roles.rs"),
    ),
    (
        "org_group_members.rs",
        include_str!("../src/org_group_members.rs"),
    ),
    ("org_groups.rs", include_str!("../src/org_groups.rs")),
    (
        "org_role_assignments.rs",
        include_str!("../src/org_role_assignments.rs"),
    ),
    (
        "org_role_permissions.rs",
        include_str!("../src/org_role_permissions.rs"),
    ),
    ("org_roles.rs", include_str!("../src/org_roles.rs")),
    ("organizations.rs", include_str!("../src/organizations.rs")),
    (
        "project_grants.rs",
        include_str!("../src/project_grants.rs"),
    ),
    (
        "scim_connections.rs",
        include_str!("../src/scim_connections.rs"),
    ),
];

/// The number of organization-addressed operations the sources declare.
///
/// Pinned so that ADDING one is a deliberate step: the new operation has to be fenced and
/// this number bumped in the same change.
///
/// It agrees with the count `deleted_environment.rs` resolves against the committed
/// contract, which is the independent check that this scan is reading the same surface
/// the document publishes. That sentence was FALSE until a review measured it: the pin
/// said 37 while the contract published 41, and the four-operation gap was `api_keys.rs`
/// being absent from `ADMIN_SOURCES` entirely. Two numbers that are supposed to agree are
/// worth nothing while nothing compares them, so the agreement is now asserted below
/// rather than only claimed here.
const ORG_ADDRESSED_OPERATIONS: usize = 55;

/// The path segment that makes an operation organization-addressed.
fn org_addressed(attr: &str) -> bool {
    attr.contains("organizations/{organization_id}")
}

/// The body of `fn name` in `source`, from its signature to the next top-level close.
fn body_of<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let sig = format!("fn {name}(");
    let start = source.find(&sig)?;
    let end = source[start..].find("\n}\n").map(|o| start + o)?;
    Some(&source[start..end])
}

/// Same-file functions `body` calls, by name.
fn callees(source: &str, body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (index, _) in source.match_indices("fn ") {
        let rest = &source[index + 3..];
        let Some(paren) = rest.find('(') else {
            continue;
        };
        let name = &rest[..paren];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            continue;
        }
        if body.contains(&format!("{name}(")) {
            out.insert(name.to_owned());
        }
    }
    out
}

/// Every organization-addressed operation, as `(file, handler)`.
fn org_operations() -> Vec<(&'static str, String, &'static str)> {
    let needle = concat!("#[utoipa", "::path(");
    let mut out = Vec::new();
    for (name, source) in ADMIN_SOURCES {
        for (index, _) in source.match_indices(needle) {
            let after = &source[index..];
            let Some(close) = after.find(")]") else {
                continue;
            };
            let attr = &after[..close];
            if !org_addressed(attr) {
                continue;
            }
            let tail = &after[close..];
            let Some(fn_at) = tail.find("pub async fn ") else {
                continue;
            };
            let rest = &tail[fn_at + "pub async fn ".len()..];
            let Some(paren) = rest.find('(') else {
                continue;
            };
            out.push((*name, rest[..paren].to_owned(), *source));
        }
    }
    out
}

#[test]
fn every_organization_addressed_operation_reaches_the_confinement_fence() {
    let operations = org_operations();
    assert_eq!(
        operations.len(),
        ORG_ADDRESSED_OPERATIONS,
        "the scan found {} organization-addressed operations and this pin expects {}. If \
         an operation was added, fence it and bump the number in the same change; if the \
         attribute's shape changed, this scan has stopped reading the surface and is no \
         longer checking anything. Found: {:?}",
        operations.len(),
        ORG_ADDRESSED_OPERATIONS,
        operations
            .iter()
            .map(|(f, h, _)| format!("{f}::{h}"))
            .collect::<Vec<_>>()
    );

    let mut unfenced = Vec::new();
    for (file, handler, source) in &operations {
        let Some(body) = body_of(source, handler) else {
            unfenced.push(format!("{file}::{handler} (body not found)"));
            continue;
        };
        if body.contains("resolve_live_org(") {
            continue;
        }
        // One level of same-file delegation. Two operations reach the fence only this
        // way; see the module header.
        let delegated = callees(source, body)
            .iter()
            .filter_map(|callee| body_of(source, callee))
            .any(|inner| inner.contains("resolve_live_org("));
        if !delegated {
            unfenced.push(format!("{file}::{handler}"));
        }
    }

    assert!(
        unfenced.is_empty(),
        "these organization-addressed operations never reach `resolve_live_org`, so a \
         credential confined to one organization is not fenced out of a sibling on them \
         and the confinement is decoration on those paths: {unfenced:?}"
    );
}

/// The scan reads the same surface the committed contract publishes.
///
/// The pin's doc comment claimed this agreement for as long as the pin existed, and it
/// was false the whole time: 37 here against 41 published, because `ADMIN_SOURCES` had no
/// entry for `api_keys.rs` and the scan therefore could not see a whole module. A scan
/// that silently covers a SUBSET of the surface answers "everything is fenced" about the
/// part it happens to read, which is the one answer it must never be able to give wrongly.
///
/// So the agreement is measured rather than asserted in prose. It resolves the operation
/// IDS, not just the counts: two sets of the same size that name different operations
/// would satisfy a count comparison.
#[test]
fn the_scan_reads_every_operation_the_committed_contract_publishes() {
    const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");
    const ORGANIZATION_PREFIX: &str =
        "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}";

    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut published = BTreeSet::new();
    for (template, entries) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(ORGANIZATION_PREFIX) {
            continue;
        }
        for (_method, entry) in entries.as_object().expect("operations") {
            published.insert(
                entry["operationId"]
                    .as_str()
                    .expect("every operation carries an id")
                    .to_owned(),
            );
        }
    }

    let scanned: BTreeSet<String> = org_operations()
        .iter()
        .filter_map(|(_file, handler, source)| operation_id_of(source, handler))
        .collect();

    let unscanned: Vec<&String> = published.difference(&scanned).collect();
    assert!(
        unscanned.is_empty(),
        "the contract publishes these organization-addressed operations and this scan \
         cannot see them, so nothing checks that they reach the confinement fence. Add \
         their file to ADMIN_SOURCES: {unscanned:?}"
    );
    let unpublished: Vec<&String> = scanned.difference(&published).collect();
    assert!(
        unpublished.is_empty(),
        "this scan reads operations the contract does not publish, so it is no longer \
         reading the surface the document describes: {unpublished:?}"
    );
}

/// The `operation_id` declared by the `#[utoipa::path]` attribute above `handler`.
fn operation_id_of(source: &str, handler: &str) -> Option<String> {
    const MARKER: &str = "operation_id = \"";
    let at = source.find(&format!("pub async fn {handler}("))?;
    // Search BACKWARDS from the handler, so the attribute read is the one immediately
    // above it. A forward scan would pair a handler with the next attribute in the file.
    let attribute = source[..at].rfind(concat!("#[utoipa", "::path("))?;
    let block = &source[attribute..at];
    let start = block.find(MARKER)? + MARKER.len();
    let end = block[start..].find('"')?;
    Some(block[start..start + end].to_owned())
}
