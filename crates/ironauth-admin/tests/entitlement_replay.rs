// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuilding the entitlement graph from the ordered event feed (issue #145 criterion 2).
//!
//! > Entitlement changes stream through the ordered events API with cursor replay, proven by
//! > rebuilding a consistent entitlement snapshot from events alone.
//!
//! # What this proves, and the one thing it does not
//!
//! Every ENTITLEMENT FACT is folded out of the feed: which memberships exist, which groups
//! exist and which of them was deleted, who is in which group, which role reaches which group
//! or membership, which role the organization hands out by default, and every withdrawal of
//! each. The snapshot is then resolved through the same ancestor closure the server uses and
//! compared, row for row, against the access-review export for the same organization.
//!
//! TWO LOOKUPS COME FROM THE MANAGEMENT API AND NOT FROM THE FEED, and pretending otherwise is
//! what sank the first attempt at this (PR #1222, closed):
//!
//!   * A ROLE'S SLUG. No `org_role.*` event carries it; every one names the role by id. It
//!     cannot be added: `org_role.created` is `additionalProperties: false`, so a new pod
//!     emitting the field and an old pod's outbox worker claiming that row is a permanent
//!     dead-letter, and `explode` fails before any per-endpoint delivery row exists so there is
//!     nothing to replay. `event_catalog.rs` documents and refuses this exact move on
//!     `token_hook.deployed`, and prescribes the alternative this file takes: "a consumer that
//!     needs it reads it from the management API".
//!   * A GROUP'S PARENT AT CREATION. `POST /groups` accepts and stores `parent_id`, and
//!     `org_group.created` carries only the group and the organization; parentage reaches the
//!     feed only through a later `org_group.reparented`. Announcing it at create would need
//!     either the same refused schema change or a second event outside the create's
//!     transaction, and an announcement that can be lost is worse than one a consumer knows to
//!     go and read.
//!
//! So the claim this file makes is narrower than the criterion's wording and is stated rather
//! than implied: the entitlement GRAPH is rebuilt from events alone; the role CATALOGUE and the
//! group TREE are synced from the API, which is what a `SailPoint`- or `Vanta`-class consumer does
//! anyway because it needs display names and descriptions the feed will never carry. Whether
//! that satisfies "from events alone" is a product decision, and #145 carries it.
//!
//! # Why the fixture is deliberately awkward
//!
//! The first attempt passed because its fixture avoided every case where the fold and the
//! resolver disagree. This one contains all of them: a role held through an ANCESTOR group, a
//! role that is DELETED while still assigned, a group that is DELETED while still holding a
//! role and still having members, a membership that is REMOVED, and an assignment that is
//! explicitly WITHDRAWN. Each drops rows from the export through `deleted_at IS NULL` at some
//! level, and each is a way for a naive fold to keep reporting access that no longer exists.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::http::StatusCode;
use common::{Harness, OPERATOR_TOKEN};
use serde_json::Value;

/// One grant path in the rebuilt snapshot, in the export's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GrantPath {
    membership_id: String,
    role_slug: String,
    source: String,
    via_group_id: String,
}

/// The entitlement state folded out of the feed.
///
/// Ids throughout, because ids are what the events carry. The slug arrives at the very end,
/// from the role catalogue, and only so the result can be compared with an export that reports
/// slugs.
#[derive(Debug, Default)]
struct Replay {
    /// Live memberships of each organization: membership id -> organization id.
    memberships: BTreeMap<String, String>,
    /// Live groups: group id -> organization id.
    groups: BTreeMap<String, String>,
    /// Group membership, by id pair.
    group_members: BTreeSet<(String, String)>,
    /// Which role reaches which group.
    group_roles: BTreeSet<(String, String)>,
    /// Which role reaches which membership directly.
    direct_roles: BTreeSet<(String, String)>,
    /// Live roles: role id -> organization id.
    roles: BTreeMap<String, String>,
    /// The organization's default role, when it has one.
    default_role: BTreeMap<String, String>,
}

impl Replay {
    /// Fold ONE envelope in.
    ///
    /// The `_ => {}` arm at the end is the dangerous one and it is why every removal the
    /// export honours is named explicitly above it. A catch-all that silently ignores
    /// `org_role.deleted` leaves the fold reporting a role the resolver stopped reporting the
    /// moment it was deleted, and the test that compares them would be measuring nothing.
    fn apply(&mut self, kind: &str, payload: &Value) {
        let field = |name: &str| payload[name].as_str().unwrap_or_default().to_owned();
        match kind {
            "organization.member_added" | "organization.service_account_added" => {
                self.memberships
                    .insert(field("membership_id"), field("organization_id"));
            }
            "organization.member_removed" | "organization.service_account_removed" => {
                self.memberships.remove(&field("membership_id"));
            }
            "organization.default_role_set" => {
                self.default_role
                    .insert(field("organization_id"), field("org_role_id"));
            }
            "organization.default_role_cleared" => {
                self.default_role.remove(&field("organization_id"));
            }
            "org_role.created" => {
                self.roles
                    .insert(field("org_role_id"), field("organization_id"));
            }
            "org_role.deleted" => {
                self.roles.remove(&field("org_role_id"));
            }
            "org_group.created" => {
                self.groups
                    .insert(field("org_group_id"), field("organization_id"));
            }
            "org_group.deleted" => {
                self.groups.remove(&field("org_group_id"));
            }
            "org_group.member_added" => {
                self.group_members
                    .insert((field("org_group_id"), field("membership_id")));
            }
            "org_group.member_removed" => {
                self.group_members
                    .remove(&(field("org_group_id"), field("membership_id")));
            }
            "org_role.assigned_to_group" => {
                self.group_roles
                    .insert((field("group_id"), field("org_role_id")));
            }
            "org_role.unassigned_from_group" => {
                self.group_roles
                    .remove(&(field("group_id"), field("org_role_id")));
            }
            "org_role.assigned_to_member" => {
                self.direct_roles
                    .insert((field("membership_id"), field("org_role_id")));
            }
            "org_role.unassigned_from_member" => {
                self.direct_roles
                    .remove(&(field("membership_id"), field("org_role_id")));
            }
            _ => {}
        }
    }

    /// Resolve the folded state into the grant paths the export would report.
    ///
    /// `parents` and `slugs` are the two API-sourced tables the module header names. Everything
    /// else in this function reads only what the fold produced.
    fn resolve(
        &self,
        organization: &str,
        parents: &BTreeMap<String, Option<String>>,
        slugs: &BTreeMap<String, String>,
    ) -> BTreeSet<GrantPath> {
        let mut paths = BTreeSet::new();
        for (membership, member_org) in &self.memberships {
            if member_org != organization {
                continue;
            }
            let mut push = |role: &String, source: &str, via: &str| {
                // A role the fold has dropped grants nothing.
                //
                // REDUNDANT TODAY, measured: removing this line leaves every assertion in this
                // file green, because `slugs` comes from the role catalogue and the catalogue
                // already excludes deleted roles, so the lookup below drops them anyway. It is
                // kept because the alternative is a fold whose correctness DEPENDS on an API
                // read -- and the whole claim of this file is that the graph comes from the
                // feed, with the API supplying names and nothing else. Keep it, and do not
                // read the surviving mutation as evidence that it does nothing.
                if self.roles.get(role).map(String::as_str) != Some(organization) {
                    return;
                }
                if let Some(slug) = slugs.get(role) {
                    paths.insert(GrantPath {
                        membership_id: membership.clone(),
                        role_slug: slug.clone(),
                        source: source.to_owned(),
                        via_group_id: via.to_owned(),
                    });
                }
            };

            for (holder, role) in &self.direct_roles {
                if holder == membership {
                    push(role, "direct", "");
                }
            }

            // THROUGH THE ANCESTOR CLOSURE: a role granted to a group reaches every member of
            // that group AND of every group beneath it, and the export names the group that
            // HOLDS the role rather than the one the member sits in.
            for (group, held_membership) in &self.group_members {
                if held_membership != membership || !self.groups.contains_key(group) {
                    continue;
                }
                let mut cursor = Some(group.clone());
                let mut walked = 0;
                while let Some(current) = cursor {
                    if !self.groups.contains_key(&current) || walked > 32 {
                        break;
                    }
                    for (holder, role) in &self.group_roles {
                        if *holder == current {
                            push(role, "group", &current);
                        }
                    }
                    cursor = parents.get(&current).cloned().flatten();
                    walked += 1;
                }
            }

            if let Some(role) = self.default_role.get(organization) {
                push(role, "default", "");
            }
        }
        paths
    }
}

/// POST and return the created id.
async fn create(h: &Harness, path: &str, key: &str, body: &Value) -> String {
    let (status, _, response) = h.post(path, key, &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "create at {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// POST where the response is not a creation (an assignment, a state change).
async fn act(h: &Harness, path: &str, key: &str, body: &Value) {
    let (status, _, response) = h.post(path, key, &body.to_string()).await;
    assert!(status.is_success(), "post to {path}: {status} {response}");
}

/// Create a user and bind it into the organization; returns the membership id.
async fn member(h: &Harness, base: &str, org: &str, handle: &str) -> String {
    let user = create(
        h,
        &format!("{base}/users"),
        &format!("er-user-{handle}"),
        &serde_json::json!({ "identifier": format!("{handle}@acme.test") }),
    )
    .await;
    create(
        h,
        &format!("{base}/organizations/{org}/memberships"),
        &format!("er-mem-{handle}"),
        &serde_json::json!({ "user_id": user }),
    )
    .await
}

/// Read the whole feed, paging on the cursor, until `sentinel` has arrived.
///
/// POLLED, and the wait is the semantics rather than flakiness dressed up. The feed gates
/// every row on `pg_snapshot_xmin(pg_current_snapshot())`, which is CLUSTER-wide, so a
/// just-committed event is withheld until every transaction open anywhere on the instance has
/// finished. One reviewer measured a single-shot read elsewhere in this crate failing 5 of 12
/// runs. PR #1222 read the feed once; that test was flaky by construction.
///
/// PAGED, separately from the polling: the default page is smaller than this scenario's event
/// count, so a single request would return a prefix and the fold would be missing whatever
/// fell off the end -- which looks exactly like a withdrawal that never happened.
async fn fold_feed(h: &Harness, tenant: &str, environment: &str, sentinel: &str) -> Replay {
    let feed = format!("/v1/tenants/{tenant}/environments/{environment}/events");
    for _ in 0..100 {
        let mut replay = Replay::default();
        let mut cursor: Option<String> = None;
        let mut saw_sentinel = false;
        loop {
            let url = match &cursor {
                None => format!("{feed}?limit=100"),
                Some(after) => format!("{feed}?limit=100&cursor={after}"),
            };
            let (status, _, body) = h.get_as(&url, OPERATOR_TOKEN).await;
            assert_eq!(status, StatusCode::OK, "event feed: {body}");
            let page: Value = serde_json::from_str(&body).expect("json");
            let events = page["events"].as_array().expect("events").clone();
            if events.is_empty() {
                break;
            }
            for item in &events {
                let envelope = &item["payload"];
                let kind = envelope["type"].as_str().unwrap_or_default();
                if kind == sentinel {
                    saw_sentinel = true;
                }
                replay.apply(kind, &envelope["payload"]);
            }
            cursor = page["next_cursor"].as_str().map(ToOwned::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        if saw_sentinel {
            return replay;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the feed never carried {sentinel}, so the fold would be reading a truncated history");
}

/// The role catalogue and the group tree, read from the MANAGEMENT API.
///
/// Named `api_` on purpose: these two are the boundary of what this test proves. See the
/// module header for why neither can come from the feed.
async fn api_role_slugs(h: &Harness, org_base: &str) -> BTreeMap<String, String> {
    let (status, _, body) = h.get(&format!("{org_base}/roles?limit=200")).await;
    assert_eq!(status, StatusCode::OK, "list roles: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|role| {
            Some((
                role["id"].as_str()?.to_owned(),
                role["slug"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

async fn api_group_parents(h: &Harness, org_base: &str) -> BTreeMap<String, Option<String>> {
    let (status, _, body) = h.get(&format!("{org_base}/groups?limit=200")).await;
    assert_eq!(status, StatusCode::OK, "list groups: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|group| {
            Some((
                group["id"].as_str()?.to_owned(),
                group["parent_id"].as_str().map(ToOwned::to_owned),
            ))
        })
        .collect()
}

/// The export's own answer, as grant paths.
async fn exported_paths(h: &Harness, org_base: &str) -> BTreeSet<GrantPath> {
    let (status, _, csv) = h.get(&format!("{org_base}/access-review?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "the export: {csv}");
    ironauth_store::access_review::parse_csv(&csv)
        .expect("the export parses")
        .into_iter()
        .filter(|row| row.fields.get("source").map(String::as_str) != Some("none"))
        .map(|row| {
            let get = |key: &str| row.fields.get(key).cloned().unwrap_or_default();
            GrantPath {
                membership_id: get("membership_id"),
                role_slug: get("role_slug"),
                source: get("source"),
                via_group_id: get("via_group_id"),
            }
        })
        .collect()
}

/// The roles, the default role and the group tree, before anybody is a member of anything.
///
/// Returns `(billing, reports, doomed_role, finance, finance_ap, doomed_group)`.
async fn seed_catalogue(h: &Harness, org_base: &str) -> (String, String, String, String, String, String) {
    // ROLES, one of which will be deleted out from under a live assignment.
    let billing = create(
        h,
        &format!("{org_base}/roles"),
        "er-role-billing",
        &serde_json::json!({ "slug": "billing-admin", "display_name": "Billing" }),
    )
    .await;
    let reports = create(
        h,
        &format!("{org_base}/roles"),
        "er-role-reports",
        &serde_json::json!({ "slug": "reports-reader", "display_name": "Reports" }),
    )
    .await;
    let baseline = create(
        h,
        &format!("{org_base}/roles"),
        "er-role-member",
        &serde_json::json!({ "slug": "member", "display_name": "Member" }),
    )
    .await;
    let doomed_role = create(
        h,
        &format!("{org_base}/roles"),
        "er-role-doomed",
        &serde_json::json!({ "slug": "temp-admin", "display_name": "Temporary" }),
    )
    .await;

    let (status, _, body) = h
        .put(
            &format!("{org_base}/default-role"),
            &serde_json::json!({ "role_id": baseline }).to_string(),
        )
        .await;
    assert!(status.is_success(), "set the default role: {body}");

    // A TWO-LEVEL TREE plus a group that will be deleted while it still holds a role and still
    // has a member.
    let finance = create(
        h,
        &format!("{org_base}/groups"),
        "er-grp-finance",
        &serde_json::json!({ "slug": "finance", "display_name": "Finance" }),
    )
    .await;
    let finance_ap = create(
        h,
        &format!("{org_base}/groups"),
        "er-grp-ap",
        &serde_json::json!({ "slug": "finance-ap", "display_name": "AP", "parent_id": finance }),
    )
    .await;
    let doomed_group = create(
        h,
        &format!("{org_base}/groups"),
        "er-grp-doomed",
        &serde_json::json!({ "slug": "doomed", "display_name": "Doomed" }),
    )
    .await;

    (billing, reports, doomed_role, finance, finance_ap, doomed_group)
}

/// Take the organization apart in the four ways the resolver honours.
///
/// Each drops rows from the export through `deleted_at IS NULL` at some level, and each is a
/// way for a fold to go on reporting access that no longer exists. They are a separate step
/// from the build so that the build reads as a working organization and this reads as what
/// happens to it.
async fn disturb(
    h: &Harness,
    org_base: &str,
    alice: &str,
    dave: &str,
    reports: &str,
    doomed_role: &str,
    doomed_group: &str,
) {
    // THE FOUR DIVERGENCES, in the order that makes each of them awkward.
    let (status, _, body) = h
        .delete(&format!("{org_base}/memberships/{alice}/roles/{reports}"))
        .await;
    assert!(status.is_success(), "withdraw the direct grant: {body}");
    let (status, _, body) = h.delete(&format!("{org_base}/roles/{doomed_role}")).await;
    assert!(status.is_success(), "delete the assigned role: {body}");
    let (status, _, body) = h.delete(&format!("{org_base}/memberships/{dave}")).await;
    assert!(status.is_success(), "remove the membership: {body}");
    let (status, _, body) = h.delete(&format!("{org_base}/groups/{doomed_group}")).await;
    assert!(status.is_success(), "delete the group: {body}");

}

/// Every id the scenario mints, so the assertions can name what they are talking about.
struct Fixture {
    billing: String,
    doomed_role: String,
    finance: String,
    doomed_group: String,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
}

/// Build the organization, then take it apart again in the four ways the export honours and a
/// naive fold does not.
async fn seed_and_disturb(h: &Harness, base: &str, org: &str) -> Fixture {
    let org_base = format!("{base}/organizations/{org}");
    let (billing, reports, doomed_role, finance, finance_ap, doomed_group) =
        seed_catalogue(h, &org_base).await;

    let alice = member(h, base, org, "alice").await;
    let bob = member(h, base, org, "bob").await;
    let carol = member(h, base, org, "carol").await;
    let dave = member(h, base, org, "dave").await;
    // ERIN EXISTS BECAUSE DAVE IS NOT ENOUGH. Dave is in the doomed group AND has his
    // membership removed, so a fold that ignores `org_group.deleted` still drops his rows for
    // the other reason -- measured, that mutant survived. Erin is in the doomed group and
    // stays a member, so the group's deletion is the ONLY thing that can take her grant away.
    let erin = member(h, base, org, "erin").await;

    // Direct grants, one of which is withdrawn again and one of which loses its ROLE.
    act(
        h,
        &format!("{org_base}/memberships/{alice}/roles"),
        "er-a-billing",
        &serde_json::json!({ "role_id": billing }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/memberships/{alice}/roles"),
        "er-a-reports",
        &serde_json::json!({ "role_id": reports }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/memberships/{carol}/roles"),
        "er-c-doomed",
        &serde_json::json!({ "role_id": doomed_role }),
    )
    .await;

    // Group grants: the role reaches bob through the group his group DESCENDS from.
    act(
        h,
        &format!("{org_base}/groups/{finance}/roles"),
        "er-g-reports",
        &serde_json::json!({ "role_id": reports }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/groups/{finance_ap}/members"),
        "er-g-bob",
        &serde_json::json!({ "membership_id": bob }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/groups/{doomed_group}/roles"),
        "er-g-doomed-role",
        &serde_json::json!({ "role_id": billing }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/groups/{doomed_group}/members"),
        "er-g-doomed-member",
        &serde_json::json!({ "membership_id": dave }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/groups/{doomed_group}/members"),
        "er-g-doomed-erin",
        &serde_json::json!({ "membership_id": erin }),
    )
    .await;

    disturb(
        h,
        &org_base,
        &alice,
        &dave,
        &reports,
        &doomed_role,
        &doomed_group,
    )
    .await;

    Fixture {
        billing,
        doomed_role,
        finance,
        doomed_group,
        alice,
        bob,
        carol,
        dave,
    }
}

/// The snapshot folded from the feed matches what the resolver reports.
///
/// The comparison is a SET EQUALITY over grant paths, both directions, because the two ways to
/// be wrong are opposite: a fold that keeps a withdrawn grant reports access nobody has, and a
/// fold that misses a live one reports an organization as safer than it is. An auditor acting
/// on either is acting on a false document.
#[tokio::test]
async fn the_snapshot_folded_from_the_feed_matches_what_the_resolver_reports() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "er-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org = create(
        &h,
        &format!("{base}/organizations"),
        "er-org",
        &serde_json::json!({ "display_name": "Acme" }),
    )
    .await;
    let org_base = format!("{base}/organizations/{org}");

    let f = seed_and_disturb(&h, &base, &org).await;
    let (billing, doomed_role, finance, doomed_group) = (
        f.billing.clone(),
        f.doomed_role.clone(),
        f.finance.clone(),
        f.doomed_group.clone(),
    );
    let (alice, bob, carol, dave) = (
        f.alice.clone(),
        f.bob.clone(),
        f.carol.clone(),
        f.dave.clone(),
    );

    // THE FOLD, waiting for the last of those to reach the feed.
    let replay = fold_feed(&h, &tenant, &environment, "org_group.deleted").await;
    // WHAT THE FOLD ITSELF SAW, asserted before anything resolves it.
    //
    // The comparison below cannot carry these three on its own, and finding that out took a
    // surviving mutant. `push` looks a role up in the API catalogue to get its slug, and the
    // catalogue already excludes DELETED roles -- so a fold that ignored `org_role.deleted`
    // entirely still produced the right answer, because the lookup silently did the filtering
    // for it. That is the API standing in for a fact the feed does carry, which is exactly the
    // confusion this file exists to avoid. Asserted here, against the folded state, where only
    // the events can have supplied the answer.
    assert!(
        !replay.roles.contains_key(&doomed_role),
        "the fold did not see `org_role.deleted`; it still believes the deleted role exists"
    );
    assert!(
        !replay.groups.contains_key(&doomed_group),
        "the fold did not see `org_group.deleted`; it still believes the deleted group exists"
    );
    assert!(
        !replay.memberships.contains_key(&dave),
        "the fold did not see `organization.member_removed`; the removed member is still live"
    );
    // AND THE CONTROLS, so the three above are not satisfied by a fold that saw nothing at all.
    assert!(
        replay.roles.contains_key(&billing) && replay.groups.contains_key(&finance),
        "the fold lost rows it was never told to drop, so the absences above prove nothing"
    );

    let parents = api_group_parents(&h, &org_base).await;
    let slugs = api_role_slugs(&h, &org_base).await;
    let rebuilt = replay.resolve(&org, &parents, &slugs);
    let exported = exported_paths(&h, &org_base).await;

    // NOT EMPTY FIRST. Two empty sets are equal, and that is the shape this whole test would
    // otherwise take if the feed went silent or the export answered nothing.
    assert!(
        !exported.is_empty(),
        "the export reported no grant at all, so the comparison below proves nothing"
    );
    assert_eq!(
        rebuilt, exported,
        "the snapshot folded from the feed disagrees with the resolver.\n\
         only in the fold (access reported that nobody has): {:?}\n\
         only in the export (access the fold missed): {:?}",
        rebuilt.difference(&exported).collect::<Vec<_>>(),
        exported.difference(&rebuilt).collect::<Vec<_>>()
    );

    // AND THE DIVERGENCES ACTUALLY HAPPENED. Every assertion above is satisfied by a fixture
    // in which none of the four removals landed, which is precisely how the first attempt at
    // this passed while proving nothing.
    let slugs_of = |membership: &str| {
        rebuilt
            .iter()
            .filter(|path| path.membership_id == membership)
            .map(|path| path.role_slug.clone())
            .collect::<BTreeSet<_>>()
    };
    assert!(
        !slugs_of(&alice).contains("reports-reader"),
        "the withdrawn direct grant is still in the snapshot"
    );
    assert!(
        !slugs_of(&carol).contains("temp-admin"),
        "the deleted role is still granted in the snapshot"
    );
    assert!(
        slugs_of(&dave).is_empty(),
        "the removed membership still holds roles in the snapshot"
    );
    assert!(
        slugs_of(&bob).contains("reports-reader"),
        "the role held through the ANCESTOR group is missing, so the closure was not folded"
    );
    assert!(
        slugs_of(&alice).contains("billing-admin") && slugs_of(&alice).contains("member"),
        "alice should still hold her direct grant and the organization default"
    );
}
