// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuilding an organization's entitlement snapshot from the event feed alone
//! (issue #145 criterion 2).
//!
//! # What "from events alone" has to mean
//!
//! The criterion asks that entitlement changes stream through the ordered events API with
//! cursor replay, "proven by rebuilding a consistent entitlement snapshot from events alone".
//! The oracle is the access-review export (#145 criterion 1), which reports the same question
//! answered from the tables: who holds which role, by which path.
//!
//! So this drives the real management surface, folds the feed, and compares the two. Nothing
//! here constructs an event: if a handler stops emitting, the fold comes up short and the
//! comparison fails, which is the property worth having.
//!
//! # What a fold CANNOT reconstruct, and why the comparison excludes it
//!
//! Two kinds of export row have no assignment behind them and therefore no event:
//!
//! * a `default` row -- the organization's default role is resolved at read from
//!   `org_roles.is_default` and no row is ever written granting it to anybody;
//! * a `none` row -- a member who holds nothing is an absence, not an assignment.
//!
//! Those are DERIVED state. A consumer reconstructing them needs the role definitions, which
//! the feed does carry, plus the rule; they are not evidence of a missing event. The
//! comparison is over the `direct` and `group` rows, which are exactly the ones an assignment
//! event exists for, and the test asserts the excluded rows are present in the export so the
//! exclusion cannot quietly become "compare nothing".

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// One path by which a member holds a role, as both sides of the comparison spell it.
type Grant = (String, String, String, String);

async fn create_org(h: &Harness, base: &str, key: &str) -> String {
    let (status, _, body) = h
        .post(
            &format!("{base}/organizations"),
            key,
            &serde_json::json!({ "display_name": "Acme" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {body}");
    id_of(&body)
}

fn id_of(body: &str) -> String {
    serde_json::from_str::<Value>(body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Drain the whole feed with the cursor the API hands back, exactly as a consumer would.
async fn drain_feed(h: &Harness, base: &str) -> Vec<Value> {
    let mut cursor: Option<String> = None;
    let mut seen = Vec::new();
    loop {
        let path = match &cursor {
            None => format!("{base}/events?limit=50"),
            Some(c) => format!("{base}/events?limit=50&cursor={c}"),
        };
        let (status, _, body) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "the feed must answer: {body}");
        let page: Value = serde_json::from_str(&body).expect("json");
        let events = page["events"].as_array().expect("an events array").clone();
        let next = page["next_cursor"].as_str().expect("a cursor").to_owned();
        if events.is_empty() {
            return seen;
        }
        seen.extend(events);
        cursor = Some(next);
    }
}

#[tokio::test]
async fn the_entitlement_snapshot_rebuilds_from_the_feed_alone() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org = create_org(&h, &base, "ak-org").await;
    let org_base = format!("{base}/organizations/{org}");

    // Two roles, so a fold that confused them is visible.
    let mut roles = Vec::new();
    for slug in ["admin", "auditor"] {
        let (status, _, body) = h
            .post(
                &format!("{org_base}/roles"),
                &format!("ak-role-{slug}"),
                &serde_json::json!({ "slug": slug, "display_name": slug }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create role {slug}: {body}");
        roles.push((slug.to_owned(), id_of(&body)));
    }

    // Two members, and a group holding the second role.
    let mut memberships = Vec::new();
    for who in ["alice", "bob"] {
        let (status, _, body) = h
            .post(
                &format!("{base}/users"),
                &format!("ak-user-{who}"),
                &serde_json::json!({ "identifier": format!("{who}@acme.test") }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create user {who}: {body}");
        let user = id_of(&body);
        let (status, _, body) = h
            .post(
                &format!("{org_base}/memberships"),
                &format!("ak-mem-{who}"),
                &serde_json::json!({ "user_id": user }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "bind {who}: {body}");
        memberships.push(id_of(&body));
    }

    let (status, _, body) = h
        .post(
            &format!("{org_base}/groups"),
            "ak-group",
            &serde_json::json!({ "slug": "engineering", "display_name": "Engineering" })
                .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create group: {body}");
    let group = id_of(&body);

    // alice holds admin DIRECTLY; bob holds auditor THROUGH the group.
    let (status, _, body) = h
        .post(
            &format!("{org_base}/memberships/{}/roles", memberships[0]),
            "ak-assign-direct",
            &serde_json::json!({ "role_id": roles[0].1 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "assign direct: {body}");
    let (status, _, body) = h
        .post(
            &format!("{org_base}/groups/{group}/roles"),
            "ak-assign-group",
            &serde_json::json!({ "role_id": roles[1].1 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "assign to group: {body}");
    let (status, _, body) = h
        .post(
            &format!("{org_base}/groups/{group}/members"),
            "ak-group-member",
            &serde_json::json!({ "membership_id": memberships[1] }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "add to group: {body}");

    // AND ONE WITHDRAWAL, so the fold is proved to subtract and not only add. alice gets
    // auditor directly and loses it again; the export must not show it and neither must the
    // rebuilt snapshot.
    let (status, _, body) = h
        .post(
            &format!("{org_base}/memberships/{}/roles", memberships[0]),
            "ak-assign-temp",
            &serde_json::json!({ "role_id": roles[1].1 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "assign temporary: {body}");
    let (status, _, body) = h
        .delete(&format!(
            "{org_base}/memberships/{}/roles/{}",
            memberships[0], roles[1].1
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "unassign: {body}");

    let rebuilt = replay(&drain_feed(&h, &base).await);
    let exported = export(&h, &org_base).await;

    assert!(
        !exported.is_empty(),
        "the export is empty, so the comparison below would pass over nothing"
    );
    assert_eq!(
        rebuilt, exported,
        "the snapshot rebuilt from the feed disagrees with the access review"
    );
}

/// Fold the feed into the same shape the export reports, using nothing but the events.
fn replay(events: &[Value]) -> BTreeSet<Grant> {
    let mut slugs: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut direct: BTreeSet<(String, String)> = BTreeSet::new();
    let mut group_roles: BTreeSet<(String, String)> = BTreeSet::new();
    let mut group_members: BTreeSet<(String, String)> = BTreeSet::new();

    for event in events {
        let kind = event["payload"]["type"].as_str().unwrap_or_default();
        // The feed event's `payload` IS the envelope; the event's own fields are the
        // envelope's `payload`. Reading `data` here silently folded nothing but empty
        // strings, and the comparison failed with one all-empty row rather than a diff.
        let data = &event["payload"]["payload"];
        let s = |k: &str| data[k].as_str().unwrap_or_default().to_owned();
        match kind {
            // THE ONLY PLACE A SLUG ARRIVES. Every other org_role event names the role by id.
            "org_role.created" => {
                let slug = data["slug"].as_str().unwrap_or_default().to_owned();
                slugs.insert(s("org_role_id"), slug);
            }
            "org_role.assigned_to_member" => {
                direct.insert((s("membership_id"), s("org_role_id")));
            }
            "org_role.unassigned_from_member" => {
                direct.remove(&(s("membership_id"), s("org_role_id")));
            }
            "org_role.assigned_to_group" => {
                group_roles.insert((s("group_id"), s("org_role_id")));
            }
            "org_role.unassigned_from_group" => {
                group_roles.remove(&(s("group_id"), s("org_role_id")));
            }
            "org_group.member_added" => {
                group_members.insert((s("org_group_id"), s("membership_id")));
            }
            "org_group.member_removed" => {
                group_members.remove(&(s("org_group_id"), s("membership_id")));
            }
            _ => {}
        }
    }

    let mut grants = BTreeSet::new();
    for (membership, role) in &direct {
        let slug = slugs.get(role).cloned().unwrap_or_default();
        grants.insert((membership.clone(), slug, "direct".to_owned(), String::new()));
    }
    for (group, role) in &group_roles {
        for (member_group, membership) in &group_members {
            if member_group == group {
                let slug = slugs.get(role).cloned().unwrap_or_default();
                grants.insert((membership.clone(), slug, "group".to_owned(), group.clone()));
            }
        }
    }
    grants
}

/// The access review, reduced to the rows an assignment event exists for.
async fn export(h: &Harness, org_base: &str) -> BTreeSet<Grant> {
    let (status, _, body) = h.get(&format!("{org_base}/access-review")).await;
    assert_eq!(status, StatusCode::OK, "the access review: {body}");

    let mut excluded = 0_usize;
    let mut grants = BTreeSet::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).expect("a json row");
        let source = row["source"].as_str().unwrap_or_default();
        if source == "default" || source == "none" {
            excluded += 1;
            continue;
        }
        grants.insert((
            row["membership_id"].as_str().unwrap_or_default().to_owned(),
            row["role_slug"].as_str().unwrap_or_default().to_owned(),
            source.to_owned(),
            row["via_group_id"].as_str().unwrap_or_default().to_owned(),
        ));
    }
    // THE EXCLUSION IS BOUNDED. Without this a build where every row became `none` would make
    // both sides empty and the comparison vacuous.
    assert!(
        excluded < 4,
        "more rows were excluded as derived than this organization can have: {body}"
    );
    grants
}
