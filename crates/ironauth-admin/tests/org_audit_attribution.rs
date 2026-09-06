// SPDX-License-Identifier: MIT OR Apache-2.0

//! The organization-attribution coverage ratchet (issue #110).
//!
//! PR #706 added `audit_log.organization_id` and the `ActingContext::in_organization` seam
//! that fills it, and NO handler calls it yet. That is a safe state only while it is a
//! MEASURED one: per-organization SIEM streams select on this column, and a per-org stream
//! shipped over an all-NULL column delivers nothing while reporting healthy. An operator
//! would conclude their org has no admin activity.
//!
//! So the gap is a number here, and it may only FALL. An operation whose path is scoped to
//! an organization is an operation whose audit row should name that organization; every one
//! that does not yet is counted, and the ceiling comes down as handlers adopt the seam.
//!
//! # Why this fails in both directions
//!
//! A ratchet that only catches a RISE lets an improvement go unrecorded, and the next
//! reader cannot tell whether the remaining gap is real or stale. Adopting the seam without
//! lowering the ceiling fails too, which forces the number to stay honest.
//!
//! # The coarseness, stated
//!
//! Attribution is tracked per OPERATION by an explicit list rather than derived from the
//! source. Deriving it would mean matching a handler function to its `utoipa` path and then
//! proving that path's body reaches `in_organization`, which a scan cannot do honestly
//! across helper calls. An explicit list is checkable in the other direction instead: every
//! entry must really be an org-scoped operation, so the list cannot be padded with names
//! that do not exist.

use std::collections::BTreeSet;

/// One function's source text, from its signature to the first column-zero `}`.
///
/// The same narrow reader `org_confinement_surface.rs` uses. It is a text scan and says
/// so: it cannot follow a call into another module, which is why the caller also reads
/// the same-file callees and why a handler that delegated attribution across a module
/// boundary would fail this check rather than pass it silently.
fn body_of<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let start = source.find(&format!("fn {name}("))?;
    let end = source[start..].find("\n}\n").map(|offset| start + offset)?;
    Some(&source[start..end])
}

/// The handler function name serving `operation`, resolved through its `operation_id`.
fn handler_name(source: &str, operation: &str) -> Option<String> {
    let marker = format!("operation_id = \"{operation}\"");
    let at = source.find(&marker)?;
    let tail = &source[at..];
    let close = tail.find(")]")?;
    let after = &tail[close..];
    let fn_at = after.find("pub async fn ")?;
    let rest = &after[fn_at + "pub async fn ".len()..];
    let paren = rest.find('(')?;
    Some(rest[..paren].to_owned())
}

/// The handler's own body plus the bodies of the same-file functions it calls.
///
/// One level of call depth, deliberately. Attribution in this crate is applied either in
/// the handler or in a small resolver beside it (`resolve_live_org` and friends), and a
/// deeper walk over a text scan would start matching names it cannot really resolve.
fn handler_body_and_callees(source: &str, operation: &str) -> Option<String> {
    let name = handler_name(source, operation)?;
    let body = body_of(source, &name)?;
    let mut reachable = body.to_owned();
    for (index, _) in source.match_indices("fn ") {
        let rest = &source[index + 3..];
        let Some(paren) = rest.find('(') else {
            continue;
        };
        let callee = &rest[..paren];
        if callee.is_empty()
            || !callee
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        if callee != name && body.contains(&format!("{callee}(")) {
            if let Some(callee_body) = body_of(source, callee) {
                reachable.push_str(callee_body);
            }
        }
    }
    Some(reachable)
}

/// Operations whose handler attributes its audit row to the organization in its path.
///
/// #706 shipped the column and the seam; this list is where adoption becomes visible.
const ORG_ATTRIBUTED: &[&str] = &[
    "addOrgGroupMember",
    "assignOrgGroupRole",
    "assignOrgMembershipRole",
    "assignOrgRolePermission",
    "clearOrgDefaultRole",
    "createMembership",
    "createOrgGroup",
    "createOrgRole",
    "createOrganizationApiKey",
    "createPortalLink",
    "createProjectGrant",
    "createScimConnection",
    "createScimPushConnection",
    "createServiceAccountMembership",
    "decideAgentVaultApproval",
    "deleteMembership",
    "deleteOrgGroup",
    "deleteOrgRole",
    "deleteOrganization",
    "deleteScimPushConnection",
    "disableOrganization",
    "enableOrganization",
    "registerAgent",
    "removeOrgGroupMember",
    "revokeOrganizationApiKey",
    "revokeScimConnection",
    "rotateOrganizationApiKey",
    "setAgentState",
    "setScimPushConnectionActive",
    "setOrgDefaultRole",
    "setOrgGroupParent",
    "storeAgentVaultConnection",
    "unassignOrgGroupRole",
    "unassignOrgMembershipRole",
    "unassignOrgRolePermission",
    "updateOrgGroup",
    "updateOrgRole",
    "withdrawProjectGrant",
];

/// How many organization-scoped WRITE operations do not yet attribute their audit rows.
///
/// ZERO. Every organization-scoped write now names its organization on the audit row.
///
/// It may only rise back through this constant, so an org-scoped write added later
/// without attribution fails here rather than silently shipping an event a per-org SIEM
/// stream will never deliver.
///
/// It counts writes only: a read produces no audit row, so it has nothing to attribute,
/// and an earlier version of this counter included reads, which put a floor under the
/// number and made zero unreachable.
///
/// A note on an earlier claim, corrected: the organization delete, disable, enable and
/// project-grant withdrawal were once described here as unable to take the same adoption
/// because a disabled or deleted organization is not one `resolve_live_org` returns. That
/// was wrong. All four resolve through it exactly as the others do; they simply bind the
/// result to `id`, which is why a scan keyed on `org_id` missed them.
/// RAISED 0 -> 1 WHEN THE DENOMINATOR GREW, and the distinction matters: nothing regressed.
///
/// This counter used to ask only whether a documented PATH named an organization. Widening it
/// to operations whose organization arrives in the request BODY brought `createLogStream` into
/// view for the first time, and it attributes nothing -- so the number rose because the
/// question got bigger, not because a write lost its attribution.
///
/// WHY IT IS NOT FIXED IN THE SAME CHANGE. `createLogStream` does not write an audit row at
/// all. `log_streams()` exists only on the unaudited `ScopedStore`; there is no acting path to
/// attach an actor or an organization to, so closing this means giving the log-stream
/// subsystem an audited write path, which is a different change in a different area. Raising
/// the ceiling is the honest record of a gap that was always there and is now measured.
///
/// It may still only rise THROUGH THIS CONSTANT, so a newly added organization-scoped write
/// that forgets `.in_organization(..)` fails here exactly as before.
const UNATTRIBUTED_CEILING: usize = 1;

/// Where each attributed operation's handler lives, so the claim can be CHECKED.
///
/// Without this, `ORG_ATTRIBUTED` is a list of assertions nobody verifies, and the ceiling
/// falls by editing a constant.
///
/// The check is per HANDLER, not per file. It used to be per file, a bare
/// `source.contains(".in_organization(")`, and the review that added
/// `createServiceAccountMembership` showed exactly what that costs: `memberships.rs`
/// already contained the call for `createMembership`, so deleting the call from the NEW
/// handler left the test green. A ceiling of zero cannot rest on a check that cannot see
/// the handler it names. [`handler_body_and_callees`] resolves the `operation_id` to its
/// function and reads that function plus the same-file functions it calls, which is the
/// granularity `org_confinement_surface.rs` already uses for the confinement fence.
const ATTRIBUTED_SOURCES: &[(&str, &str)] = &[
    // The outbound provisioning writes (issue #137). All three attribute through
    // `.in_organization(org_id)`; they did not, and `audit_log.organization_id` was NULL for
    // every one of them, so a per-organization log stream saw none of an operator re-pointing
    // that organization's directory.
    (
        "createScimPushConnection",
        include_str!("../src/scim_push_connections.rs"),
    ),
    (
        "setScimPushConnectionActive",
        include_str!("../src/scim_push_connections.rs"),
    ),
    (
        "deleteScimPushConnection",
        include_str!("../src/scim_push_connections.rs"),
    ),
    (
        "storeAgentVaultConnection",
        include_str!("../src/agents.rs"),
    ),
    ("decideAgentVaultApproval", include_str!("../src/agents.rs")),
    ("registerAgent", include_str!("../src/agents.rs")),
    ("setAgentState", include_str!("../src/agents.rs")),
    (
        "createServiceAccountMembership",
        include_str!("../src/memberships.rs"),
    ),
    (
        "createOrganizationApiKey",
        include_str!("../src/api_keys.rs"),
    ),
    (
        "revokeOrganizationApiKey",
        include_str!("../src/api_keys.rs"),
    ),
    (
        "createScimConnection",
        include_str!("../src/scim_connections.rs"),
    ),
    (
        "revokeScimConnection",
        include_str!("../src/scim_connections.rs"),
    ),
    (
        "rotateOrganizationApiKey",
        include_str!("../src/api_keys.rs"),
    ),
    ("createMembership", include_str!("../src/memberships.rs")),
    ("deleteMembership", include_str!("../src/memberships.rs")),
    (
        "addOrgGroupMember",
        include_str!("../src/org_group_members.rs"),
    ),
    (
        "removeOrgGroupMember",
        include_str!("../src/org_group_members.rs"),
    ),
    ("createOrgGroup", include_str!("../src/org_groups.rs")),
    ("deleteOrgGroup", include_str!("../src/org_groups.rs")),
    ("setOrgGroupParent", include_str!("../src/org_groups.rs")),
    ("updateOrgGroup", include_str!("../src/org_groups.rs")),
    (
        "assignOrgGroupRole",
        include_str!("../src/org_role_assignments.rs"),
    ),
    (
        "assignOrgMembershipRole",
        include_str!("../src/org_role_assignments.rs"),
    ),
    (
        "unassignOrgGroupRole",
        include_str!("../src/org_role_assignments.rs"),
    ),
    (
        "unassignOrgMembershipRole",
        include_str!("../src/org_role_assignments.rs"),
    ),
    (
        "assignOrgRolePermission",
        include_str!("../src/org_role_permissions.rs"),
    ),
    (
        "unassignOrgRolePermission",
        include_str!("../src/org_role_permissions.rs"),
    ),
    ("clearOrgDefaultRole", include_str!("../src/org_roles.rs")),
    ("createOrgRole", include_str!("../src/org_roles.rs")),
    ("deleteOrgRole", include_str!("../src/org_roles.rs")),
    ("setOrgDefaultRole", include_str!("../src/org_roles.rs")),
    ("updateOrgRole", include_str!("../src/org_roles.rs")),
    (
        "createProjectGrant",
        include_str!("../src/project_grants.rs"),
    ),
    (
        "deleteOrganization",
        include_str!("../src/organizations.rs"),
    ),
    (
        "disableOrganization",
        include_str!("../src/organizations.rs"),
    ),
    (
        "enableOrganization",
        include_str!("../src/organizations.rs"),
    ),
    (
        "withdrawProjectGrant",
        include_str!("../src/project_grants.rs"),
    ),
    // The portal link mint (issue #140). The one operation here whose organization arrives
    // in the request BODY, which is exactly why it was invisible to this sweep until the
    // denominator below learned to look for it.
    ("createPortalLink", include_str!("../src/portal_links.rs")),
];

/// Operations that name their organization in the REQUEST BODY rather than the path.
///
/// SHARED WITH `org_confinement_surface.rs`, whose denominator had the identical blind
/// spot and whose version of it shipped a confinement bypass; see the module.
#[path = "common/body_addressed.rs"]
mod body_addressed;
use body_addressed::body_addressed_operations;

/// Every operation whose documented surface is scoped to an organization, by path or by
/// request body.
fn org_scoped_operations() -> BTreeSet<String> {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/management.json"))
            .expect("the committed management spec parses");
    let mut found = BTreeSet::new();
    let paths = spec["paths"].as_object().expect("the spec has paths");
    for (path, item) in paths {
        if !path.contains("{organization_id}") {
            continue;
        }
        let operations = item.as_object().expect("a path item is an object");
        for (method, operation) in operations {
            // WRITES only. A read writes no audit row, so it has nothing to attribute and
            // counting it inflates the gap with operations that can never close it. The
            // first version of this counter included reads, which made a ceiling of zero
            // unreachable and the number meaningless as a measure of progress.
            if method.eq_ignore_ascii_case("get") {
                continue;
            }
            if let Some(id) = operation.get("operationId").and_then(|id| id.as_str()) {
                found.insert(id.to_string());
            }
        }
    }

    // THE WRITES WHOSE ORGANIZATION IS IN THE BODY, which the path filter above cannot
    // see and therefore silently excused. `createPortalLink` hands configuration
    // authority over one organization to somebody outside the deployment, so it is the
    // last write that should be missing from that organization's own log stream -- and it
    // was, because the sweep measuring the gap did not count it as organization-scoped.
    //
    // Each is resolved against the document rather than trusted, so a renamed or removed
    // operation fails here instead of quietly narrowing the denominator the way the
    // original path filter did.
    for id in body_addressed_operations() {
        // WRITES ONLY, for the reason the path filter above gives: a read produces no audit
        // row, so it has nothing to attribute. The derivation does not know that -- it reads
        // request schemas, and a GET carrying a body would qualify -- so the method filter is
        // applied here rather than assumed.
        let is_write = paths.values().any(|item| {
            item.as_object().is_some_and(|methods| {
                methods.iter().any(|(method, operation)| {
                    !method.eq_ignore_ascii_case("get")
                        && operation.get("operationId").and_then(|v| v.as_str())
                            == Some(id.as_str())
                })
            })
        });
        if is_write {
            found.insert(id);
        }
    }
    found
}

/// The organization-attribution gap is counted, and may only fall.
#[test]
fn the_organization_attribution_gap_is_counted_and_may_only_fall() {
    let org_scoped = org_scoped_operations();

    // Anti-vacuity: a spec that failed to parse into anything, or a path filter that
    // matched nothing, would make every assertion below trivially true.
    assert!(
        org_scoped.len() >= 20,
        "found only {} organization-scoped WRITE operations, which means the scan is \
         broken rather than the surface having shrunk that far",
        org_scoped.len()
    );

    // No stale entries: an attributed name must be a real org-scoped operation, so the
    // list cannot be padded to make the gap look smaller than it is.
    for attributed in ORG_ATTRIBUTED {
        assert!(
            org_scoped.contains(*attributed),
            "`{attributed}` is listed as attributing its audit row to an organization, but \
             it is not an organization-scoped operation in the committed spec"
        );
    }

    // Every claim is checked against the source that is supposed to back it.
    for operation in ORG_ATTRIBUTED {
        let source = ATTRIBUTED_SOURCES
            .iter()
            .find(|(name, _)| name == operation)
            .unwrap_or_else(|| {
                panic!(
                    "`{operation}` is listed as attributed but has no entry in \
                     ATTRIBUTED_SOURCES, so the claim is unverifiable"
                )
            })
            .1;
        let reachable = handler_body_and_callees(source, operation).unwrap_or_else(|| {
            panic!(
                "`{operation}` has an ATTRIBUTED_SOURCES entry but no handler could be \
                 resolved from it. Either the operation_id is not in that file, or the \
                 `#[utoipa::path]`/`pub async fn` shape changed and this scan has stopped \
                 reading the surface"
            )
        });
        assert!(
            reachable.contains(".in_organization("),
            "`{operation}` is listed as attributed but neither its handler nor any \
             same-file function it calls invokes `.in_organization(..)`, so its audit \
             rows carry no organization"
        );
    }

    let attributed: BTreeSet<String> = ORG_ATTRIBUTED.iter().map(|id| (*id).to_string()).collect();
    let unattributed: Vec<&String> = org_scoped.difference(&attributed).collect();

    // The other direction: adopting the seam without lowering the ceiling leaves a number
    // that no longer describes anything.
    // ONE exact assertion rather than a `<=` plus an `==`. At a ceiling of zero the
    // inequality is vacuous (a length is never below zero), and clippy says so. Exact
    // equality already fails in both directions: a new unattributed write raises the count
    // above the constant, and lowering the count without lowering the constant fails too.
    assert_eq!(
        unattributed.len(),
        UNATTRIBUTED_CEILING,
        "the organization-attribution count is {} but UNATTRIBUTED_CEILING says \
         {UNATTRIBUTED_CEILING}. If it ROSE, an organization-scoped write was added \
         without calling `ActingStore::in_organization(..)`, and its events will never \
         reach a per-organization stream. If it FELL, lower the constant in the same \
         change. Unattributed: {unattributed:?}",
        unattributed.len()
    );
}

/// Per-organization SIEM streams stay unavailable while NOTHING is attributed.
///
/// This is the guard that enforced the ordering. `log_streams` could not gain an
/// organization column while every audit row was NULL: such a stream would match nothing,
/// deliver nothing, and report healthy, and the operator would conclude their organization
/// had no admin activity.
///
/// The ordering held. 0138 added the dimension, the writes adopted it, and only then did
/// 0139 add the column. The guard stays because the condition it protects is permanent: if
/// attribution were ever removed wholesale, offering per-org streams would become a lie
/// again.
#[test]
fn per_org_streams_are_not_offered_while_no_audit_row_is_attributed() {
    // BOTH migrations, because the column can arrive in either. Checking only the table's
    // CREATE would pass vacuously the moment a later ALTER adds it, which is exactly what
    // 0139 does.
    let migration = concat!(
        include_str!("../../ironauth-store/migrations/0137_log_streams.sql"),
        "\n",
        include_str!("../../ironauth-store/migrations/0139_log_stream_organization.sql"),
    );
    // COMMENT LINES STRIPPED FIRST. 0137's prose explains at length why it carries no
    // organization column, so a plain `contains` matches that explanation and reports a
    // column that does not exist. The first version of this guard did exactly that: a
    // scan that matches its own commentary manufactures its own evidence.
    let sql: String = migration
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let attributed_any = !ORG_ATTRIBUTED.is_empty();
    let stream_has_org_column = sql.contains("organization_id");

    // Anti-vacuity: if stripping left nothing, the guard below would pass for a reason
    // unrelated to what it claims.
    assert!(
        sql.contains("CREATE TABLE log_streams"),
        "stripping comments removed the SQL itself, so this guard is checking nothing"
    );

    if !attributed_any {
        assert!(
            !stream_has_org_column,
            "log_streams gained an organization_id column while NO audit row is attributed \
             to an organization. Such a stream matches nothing, delivers nothing, and \
             reports healthy. Adopt the attribution seam first and lower \
             UNATTRIBUTED_CEILING, then add the column."
        );
    }
}
