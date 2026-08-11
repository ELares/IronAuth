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

/// Operations whose handler attributes its audit row to the organization in its path.
///
/// #706 shipped the column and the seam; this list is where adoption becomes visible.
const ORG_ATTRIBUTED: &[&str] = &[
    // The first adopter, and the proof the ratchet falls rather than only rising.
    "createOrgRole",
];

/// How many organization-scoped operations do NOT yet attribute their audit rows.
///
/// This may only FALL. It was 40 when #706 landed the seam with no adopters.
/// Lower it in the same change that adopts the seam; the test below fails if you adopt
/// without lowering, so the number cannot go stale.
const UNATTRIBUTED_CEILING: usize = 39;

/// Where each attributed operation's handler lives, so the claim can be CHECKED.
///
/// Without this, `ORG_ATTRIBUTED` is a list of assertions nobody verifies, and the ceiling
/// falls by editing a constant. The check is per FILE, which is coarse: it proves the
/// module calls the seam, not that this particular handler does. That is the same
/// granularity `ADMIN_SOURCES` uses elsewhere in this crate, and it is honest about what
/// it catches, which is a list padded with a module that never adopted the seam at all.
const ATTRIBUTED_SOURCES: &[(&str, &str)] =
    &[("createOrgRole", include_str!("../src/org_roles.rs"))];

/// Every operation whose documented path is scoped to an organization.
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
        for operation in operations.values() {
            if let Some(id) = operation.get("operationId").and_then(|id| id.as_str()) {
                found.insert(id.to_string());
            }
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
        org_scoped.len() >= 30,
        "found only {} organization-scoped operations, which means the scan is broken \
         rather than the surface having shrunk that far",
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
        assert!(
            source.contains(".in_organization("),
            "`{operation}` is listed as attributed but its module never calls \
             `.in_organization(..)`, so its audit rows carry no organization"
        );
    }

    let attributed: BTreeSet<String> = ORG_ATTRIBUTED.iter().map(|id| (*id).to_string()).collect();
    let unattributed: Vec<&String> = org_scoped.difference(&attributed).collect();

    assert!(
        unattributed.len() <= UNATTRIBUTED_CEILING,
        "the number of organization-scoped operations whose audit row does NOT name its \
         organization rose to {}. It may only fall. Call \
         `ActingStore::in_organization(..)` on the handler's acting store, then list the \
         operation in ORG_ATTRIBUTED. Unattributed: {unattributed:?}",
        unattributed.len()
    );

    // The other direction: adopting the seam without lowering the ceiling leaves a number
    // that no longer describes anything.
    assert_eq!(
        unattributed.len(),
        UNATTRIBUTED_CEILING,
        "the gap improved to {} but UNATTRIBUTED_CEILING still says {UNATTRIBUTED_CEILING}. \
         Lower it in the same change, or the next reader cannot tell a real gap from a \
         stale one",
        unattributed.len()
    );
}

/// Per-organization SIEM streams stay unavailable while the gap is total.
///
/// This is the guard that matters. `log_streams` deliberately has no organization column
/// yet (migration 0137 says why), and it must not gain one while every audit row is NULL:
/// such a stream would match nothing, deliver nothing, and report healthy, and the operator
/// would conclude their organization had no admin activity.
#[test]
fn per_org_streams_are_not_offered_while_no_audit_row_is_attributed() {
    let migration = include_str!("../../ironauth-store/migrations/0137_log_streams.sql");
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
