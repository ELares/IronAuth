// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuilding the entitlement graph from the ordered event feed (issue #145 criterion 2).
//!
//! > Entitlement changes stream through the ordered events API with cursor replay, proven by
//! > rebuilding a consistent entitlement snapshot from events alone.
//!
//! # What this proves, and the one thing it does not
//!
//! The entitlement facts are folded out of the feed: which memberships exist and whose they
//! are, which groups exist and how they nest, who is in which group, which role reaches which
//! group or membership, which role the organization hands out by default, which time-boxed
//! grants an approver has approved, whether the organization is still active, and every
//! withdrawal of each. All four of the export's grant sources are in the comparison. The snapshot is then resolved
//! through an ancestor walk mirroring the server's closure and compared against the
//! access-review export for the same organization.
//!
//! The comparison is a SET EQUALITY over four of the export's nine columns -- the membership,
//! the role slug, the source and the group -- and not a row-for-row comparison of the file: the
//! remaining five are the organization, the principal kind, the subject and the two time-boxed
//! columns, which say who a row is ABOUT rather than what it grants.
//!
//! ONE LOOKUP COMES FROM THE MANAGEMENT API AND NOT FROM THE FEED, and pretending otherwise is
//! what sank the first attempt at this (PR #1222, closed). It was two until the group tree
//! moved into the feed; see the section after this one.
//!
//!   * A ROLE'S SLUG. No `org_role.*` event carries it; every one names the role by id. It
//!     cannot be added: `org_role.created` is `additionalProperties: false`, so a new pod
//!     emitting the field and an old pod's outbox worker claiming that row is a permanent
//!     dead-letter, and `explode` fails before any per-endpoint delivery row exists so there is
//!     nothing to replay. `event_catalog.rs` documents and refuses this exact move on
//!     `token_hook.deployed`, and prescribes the alternative this file takes: "a consumer that
//!     needs it reads it from the management API".
//!
//! # The group's parent was on that list and should not have been
//!
//! It was there on the grounds that announcing it at create would need
//! either the same refused schema change or a second event outside the create's transaction.
//! That was wrong, and a review caught it: `create_with_event` enqueues through
//! `enqueue_domain_event(tx, ..)` INSIDE the write's transaction, so a second event costs a
//! signature widened from one event to a slice and nothing else. It is done, the create now
//! announces `org_group.reparented` beside `org_group.created`, and the tree comes from the
//! feed. It was also a live defect rather than only a gap in this test: a consumer mirroring
//! the tree attached every nested group to the root, and then resolved the wrong members for
//! every role granted to a parent.
//!
//! So the claim this file makes is narrower than the criterion's wording and is stated rather
//! than implied: the entitlement GRAPH is rebuilt from events alone, the group tree included;
//! the role CATALOGUE is synced from the API, which is what a `SailPoint`- or `Vanta`-class
//! consumer does anyway because it needs display names and descriptions the feed will never
//! carry. Whether that satisfies "from events alone" is a product decision, and #145 carries
//! it.
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

/// An approved time-boxed grant, as the decision announced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TimeBoxed {
    organization: String,
    subject: String,
    role_slug: String,
    granted_until_unix_ms: i64,
}

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
    /// Each group's parent, from the feed. Absent means nobody ever announced one.
    group_parents: BTreeMap<String, Option<String>>,
    /// The user or service account behind each membership.
    membership_subject: BTreeMap<String, String>,
    /// Organizations that are disabled or deleted, and so resolve nothing.
    inactive_orgs: BTreeSet<String>,
    /// Subjects whose own row is gone, taking their memberships' grants with it.
    dead_subjects: BTreeSet<String>,
    /// Approved time-boxed grants, each with the instant it stops granting.
    time_boxed: BTreeSet<TimeBoxed>,
}

impl Replay {
    /// Fold ONE envelope in.
    ///
    /// The `_ => {}` arm at the end is the dangerous one: anything the resolver honours and
    /// this match does not name is access the fold goes on reporting after the product has
    /// revoked it. The first version of this file claimed the arms above were exhaustive over
    /// "every removal the export honours", and they were not -- `organization.state_changed`,
    /// `organization.deleted` and `user.deleted` all fell through, and a reviewer reproduced
    /// two of them by adding the case to the fixture and watching the comparison fail.
    ///
    /// So the claim is the narrow one, in two halves that are NOT the same claim.
    ///
    /// EVERY FENCE `EFFECTIVE_CLOSURE_CTE` APPLIES HAS AN ARM HERE: the organization's state
    /// and its tombstone, the membership's, the user's, the role's, the group's, and each of
    /// the three assignment tables.
    ///
    /// THE FIXTURE REACHES ALL BUT TWO OF THEM, and both exceptions are named rather than
    /// glossed, because an arm nothing drives is an arm whose mutant survives and a reader is
    /// owed the reason.
    ///
    ///   * `organization.deleted`. A deleted organization cannot be exported at all --
    ///     `resolve_live_org` answers not-found -- so there is no second side to compare a fold
    ///     against. The arm is kept for a consumer that folds more than one organization.
    ///   * `user.deprovisioned`. Reaching it means driving the SCIM `DELETE /scim/v2/Users/{id}`
    ///     path, which needs a provisioning connection and its own credential, and that is a
    ///     SCIM fixture rather than an entitlement one. The arm is here because the fold was
    ///     WRONG without it, which is a stronger reason than coverage: see its own comment.
    ///
    /// The deadline on a time-boxed grant is a third thing this scenario cannot reach, for a
    /// different reason -- it would have to wait for one -- and
    /// `an_expired_time_boxed_grant_resolves_to_nothing` measures it directly instead.
    ///
    /// `user.deactivated` and `user.state_changed` are deliberately NOT handled: they move
    /// `users.state`, and the closure fences on `users.deleted_at`, so they change nothing the
    /// export reports. `user.deprovisioned` was on that list in round 1 and should never have
    /// been -- see its arm below.
    fn apply(&mut self, kind: &str, payload: &Value) {
        let field = |name: &str| payload[name].as_str().unwrap_or_default().to_owned();
        match kind {
            "organization.member_added" | "organization.service_account_added" => {
                self.memberships
                    .insert(field("membership_id"), field("organization_id"));
                // WHO is behind the membership, so a user's own lifecycle can reach it. The
                // closure LEFT JOINs `users u ... AND u.deleted_at IS NULL` and requires
                // `u.id IS NOT NULL`, so soft-deleting a USER empties that member's grants
                // while the membership row itself is untouched and announces nothing.
                let subject = if payload["user_id"].is_string() {
                    field("user_id")
                } else {
                    field("service_account_id")
                };
                self.membership_subject
                    .insert(field("membership_id"), subject);
            }
            "organization.member_removed" | "organization.service_account_removed" => {
                self.memberships.remove(&field("membership_id"));
            }
            // THE ORGANIZATION'S OWN LIFECYCLE. `EFFECTIVE_CLOSURE_CTE` seeds `membership` only
            // under `o.state = 'active' AND o.deleted_at IS NULL`, so a DISABLED or DELETED
            // organization resolves nothing for every one of its members -- the export still
            // lists them, each with a single `none` row. A fold without these two arms goes on
            // reporting every grant in an organization an operator has already shut off, which
            // is the coarsest revocation there is.
            "organization.state_changed" => {
                if payload["state"].as_str() == Some("active") {
                    self.inactive_orgs.remove(&field("organization_id"));
                } else {
                    self.inactive_orgs.insert(field("organization_id"));
                }
            }
            "organization.deleted" => {
                self.inactive_orgs.insert(field("organization_id"));
            }
            // A USER's lifecycle, reaching the membership through the subject recorded above.
            // `user.deleted` is the soft-delete offboarding; it cascades sessions and leaves
            // `org_memberships` alone, so nothing else on the feed says the grants are gone.
            "user.deleted" => {
                self.dead_subjects.insert(field("user_id"));
            }
            // SCIM OFFBOARDING, and it is a MEMBERSHIP removal wearing a user event's name.
            //
            // The round-1 version of this file listed `user.deprovisioned` among the events it
            // was safe to ignore, on the grounds that it only moves `users.state`. False, and
            // the more dangerous kind of false: the SCIM `DELETE /scim/v2/Users/{id}` handler
            // attaches this event to the membership SOFT-DELETE write itself
            // (`ironauth-scim/src/users.rs`, through `remove_with_event`), which emits the one
            // event it is handed and never an `organization.member_removed`. So this is the
            // ONLY announcement that a SCIM-offboarded member has lost the organization, and a
            // fold that skipped it kept resolving their grants for ever -- while the export,
            // which seeds on `m.state = 'active' AND m.deleted_at IS NULL`, dropped every one.
            "user.deprovisioned" => {
                let user = field("user_id");
                let organization = field("organization_id");
                self.memberships.retain(|membership, owner| {
                    *owner != organization
                        || self.membership_subject.get(membership) != Some(&user)
                });
            }
            "organization.default_role_set" => {
                self.default_role
                    .insert(field("organization_id"), field("org_role_id"));
            }
            "organization.default_role_cleared" => {
                self.default_role.remove(&field("organization_id"));
            }
            // THE FOURTH SOURCE the export can report. Unlike every other arm this one names
            // the role by SLUG rather than by id, because that is what the payload carries --
            // the access-request table matches on the slug too, which is why raising one for a
            // role the organization does not define is refused at the raise.
            "access_request.decided" => {
                if payload["approved"].as_bool() == Some(true) {
                    // WITH ITS DEADLINE. The resolver's fourth arm requires
                    // `agr.granted_until > $6`, so a grant that has lapsed stops granting
                    // whether or not any sweep has relabelled it. A fold that kept the grant
                    // without its deadline would report an elevation that ended hours ago --
                    // and `access_request.decided` is the only event there is, because expiry
                    // happens by a clock passing rather than by anybody writing a row.
                    self.time_boxed.insert(TimeBoxed {
                        organization: field("organization_id"),
                        subject: field("subject_id"),
                        role_slug: field("role_slug"),
                        granted_until_unix_ms: payload["granted_until_unix_ms"]
                            .as_i64()
                            .unwrap_or_default(),
                    });
                }
            }
            _ => self.apply_assignment(kind, payload),
        }
    }

    /// The arms that move ASSIGNMENT rows, split from the lifecycle ones above only because the
    /// crate bounds a function at a hundred lines. One match would read better.
    fn apply_assignment(&mut self, kind: &str, payload: &Value) {
        let field = |name: &str| payload[name].as_str().unwrap_or_default().to_owned();
        match kind {
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
            // THE EDGE, from the feed. A group created underneath a parent announces the
            // create and then the parentage, both from the create's own transaction, so a
            // consumer that folds both has the tree. An absent `parent_org_group_id` means
            // the group was moved to the root, which is why this writes `None` rather than
            // skipping.
            "org_group.reparented" => {
                let parent = payload["parent_org_group_id"]
                    .as_str()
                    .map(ToOwned::to_owned);
                self.group_parents.insert(field("org_group_id"), parent);
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
    /// `slugs` is the ONE API-sourced table left, and the module header says why. Everything
    /// else here reads only what the fold produced, the group tree included.
    fn resolve(
        &self,
        organization: &str,
        slugs: &BTreeMap<String, String>,
        now_unix_ms: i64,
    ) -> BTreeSet<GrantPath> {
        let parents = &self.group_parents;
        let mut paths = BTreeSet::new();
        // A DISABLED OR DELETED ORGANIZATION RESOLVES NOTHING, for every member at once.
        if self.inactive_orgs.contains(organization) {
            return paths;
        }
        for (membership, member_org) in &self.memberships {
            if member_org != organization {
                continue;
            }
            // ...and neither does a membership whose subject is gone.
            if self
                .membership_subject
                .get(membership)
                .is_some_and(|subject| self.dead_subjects.contains(subject))
            {
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
                // feed, with the API supplying the role CATALOGUE and nothing else. Keep it,
                // and do not read the surviving mutation as evidence that it does nothing.
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

            // THE TIME-BOXED PATH, keyed on the SUBJECT rather than the membership because
            // that is what the decision announced. The role still has to be one this
            // organization defines and still live, which is why it goes back through the same
            // id lookup as every other source rather than trusting the slug on the event.
            if let Some(subject) = self.membership_subject.get(membership) {
                for grant in &self.time_boxed {
                    if grant.organization != *organization
                        || grant.subject != *subject
                        || grant.granted_until_unix_ms <= now_unix_ms
                    {
                        continue;
                    }
                    let role = self
                        .roles
                        .iter()
                        .find(|(id, owner)| {
                            *owner == organization && slugs.get(*id) == Some(&grant.role_slug)
                        })
                        .map(|(id, _)| id.clone());
                    if let Some(role) = role {
                        push(&role, "time_boxed", "");
                    }
                }
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
    member_with_user(h, base, org, handle).await.1
}

/// The same, returning `(user id, membership id)` for a caller that needs the subject.
async fn member_with_user(
    h: &Harness,
    base: &str,
    org: &str,
    handle: &str,
) -> (String, String) {
    let user = create(
        h,
        &format!("{base}/users"),
        &format!("er-user-{handle}"),
        &serde_json::json!({ "identifier": format!("{handle}@acme.test") }),
    )
    .await;
    let membership = create(
        h,
        &format!("{base}/organizations/{org}/memberships"),
        &format!("er-mem-{handle}"),
        &serde_json::json!({ "user_id": user }),
    )
    .await;
    (user, membership)
}

/// Read the whole feed, paging on the cursor, until `sentinel` has arrived.
///
/// POLLED, and the wait is the semantics rather than flakiness dressed up. The feed gates
/// every row on `pg_snapshot_xmin(pg_current_snapshot())`, which is CLUSTER-wide, so a
/// just-committed event is withheld until every transaction open anywhere on the instance has
/// finished. One reviewer measured a single-shot read elsewhere in this crate failing 5 of 12
/// runs. PR #1222 read the feed once; that test was flaky by construction.
///
/// PAGED, and the page size is deliberately far SMALLER than the scenario's event count.
///
/// The first version asked for `limit=100`, which is the feed's own default, against a
/// scenario that emits well under a hundred events -- so it took exactly one page every time
/// and the loop below never ran twice. It claimed to exercise paging and could not have. The
/// criterion names CURSOR REPLAY, and a single request that happens to return everything
/// proves the cursor is accepted, not that it works: the thing that breaks is resuming FROM
/// one, and that only happens on the second page.
///
/// `PAGE` is five, so this scenario spans many pages and the fold is assembled across them.
/// `pages_read` is returned so the caller can refuse a run that did not actually page.
const PAGE: usize = 5;

async fn fold_feed(h: &Harness, tenant: &str, environment: &str, sentinel: &str) -> (Replay, usize) {
    let feed = format!("/v1/tenants/{tenant}/environments/{environment}/events");
    for _ in 0..100 {
        let mut replay = Replay::default();
        let mut cursor: Option<String> = None;
        let mut saw_sentinel = false;
        let mut pages_read = 0_usize;
        loop {
            let url = match &cursor {
                None => format!("{feed}?limit={PAGE}"),
                Some(after) => format!("{feed}?limit={PAGE}&cursor={after}"),
            };
            let (status, _, body) = h.get_as(&url, OPERATOR_TOKEN).await;
            assert_eq!(status, StatusCode::OK, "event feed: {body}");
            let page: Value = serde_json::from_str(&body).expect("json");
            let events = page["events"].as_array().expect("events").clone();
            if events.is_empty() {
                break;
            }
            pages_read += 1;
            for item in &events {
                let envelope = &item["payload"];
                let kind = envelope["type"].as_str().unwrap_or_default();
                if kind == sentinel {
                    saw_sentinel = true;
                }
                replay.apply(kind, &envelope["payload"]);
            }
            // The feed documents `next_cursor` as always present ("Present even when `events`
            // is empty, so a caller always has somewhere to continue"), so this is not the
            // loop's exit -- the empty page above is. It is here because a cursor that DID go
            // missing would otherwise restart the fold from the beginning of the feed on every
            // iteration, which reads as a hang rather than as a contract change.
            cursor = page["next_cursor"].as_str().map(ToOwned::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        if saw_sentinel {
            return (replay, pages_read);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the feed never carried {sentinel}, so the fold would be reading a truncated history");
}

/// The role CATALOGUE, read from the management API.
///
/// Named `api_` on purpose: this is the boundary of what this test proves, and the module
/// header says why the slug cannot come from the feed.
///
/// `api_group_parents` below is NOT that boundary any more. The tree comes from the feed now,
/// and that function is kept only so the fold's tree can be checked against the server's --
/// which is a comparison, not a source.
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

/// The group tree as the SERVER reports it, for comparison against the folded one.
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

/// The members, their grants, and the live time-boxed approval.
///
/// Returns everything later assertions name. Split from the catalogue and the removals only
/// because the crate bounds a function at a hundred lines.
struct Members {
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    erin: String,
    frank: String,
    frank_user: String,
    henry: String,
    ida: String,
    ops: String,
}

#[allow(clippy::too_many_arguments)]
async fn seed_members(
    h: &Harness,
    base: &str,
    org: &str,
    org_base: &str,
    billing: &str,
    reports: &str,
    finance: &str,
    finance_ap: &str,
    doomed_group: &str,
    doomed_role: &str,
) -> Members {
    let alice = member(h, base, org, "alice").await;
    let bob = member(h, base, org, "bob").await;
    let (carol_user, carol) = member_with_user(h, base, org, "carol").await;
    let dave = member(h, base, org, "dave").await;
    // ERIN EXISTS BECAUSE DAVE IS NOT ENOUGH. Dave is in the doomed group AND has his
    // membership removed, so a fold that ignores `org_group.deleted` still drops his rows for
    // the other reason -- measured, that mutant survived. Erin is in the doomed group and
    // stays a member, so the group's deletion is the ONLY thing that can take her grant away.
    let erin = member(h, base, org, "erin").await;
    // FRANK holds only the organization default, and his USER is soft-deleted below. That is
    // the narrowest possible case: the membership survives, no assignment is touched, and the
    // only thing that takes his access away is a fence on the users table.
    let (frank_user, frank) = member_with_user(h, base, org, "frank").await;
    let (henry, ops, ida) =
        seed_group_removal_subjects(h, base, org, org_base, finance, billing).await;

    // CAROL gets a live time-boxed grant, so the export's FOURTH source is in the comparison.
    // She is the right subject because the role she was assigned directly has been deleted, so
    // the only thing she can hold besides the default is this.
    raise_and_approve(h, base, org, &carol_user).await;

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

    Members {
        alice,
        bob,
        carol,
        dave,
        erin,
        frank,
        frank_user,
        henry,
        ida,
        ops,
    }
}

/// Two members who each exercise one removal nothing else in the fixture reaches.
///
/// Separate people on purpose: two removals on one subject mask each other, which is how the
/// group deletion went unmeasured until erin existed. Returns `(henry, ops group, ida)`.
async fn seed_group_removal_subjects(
    h: &Harness,
    base: &str,
    org: &str,
    org_base: &str,
    finance: &str,
    billing: &str,
) -> (String, String, String) {
    // Henry joins `finance` and is then removed FROM THE GROUP -- the group survives, his
    // membership survives, and only `org_group.member_removed` says the inherited role is gone.
    let henry = member(h, base, org, "henry").await;
    act(
        h,
        &format!("{org_base}/groups/{finance}/members"),
        "er-g-henry",
        &serde_json::json!({ "membership_id": henry }),
    )
    .await;
    // Ida sits in a group whose ROLE is then unassigned. The group survives, she stays in it,
    // and only `org_role.unassigned_from_group` says the role no longer reaches her.
    let ops = create(
        h,
        &format!("{org_base}/groups"),
        "er-grp-ops",
        &serde_json::json!({ "slug": "ops", "display_name": "Ops" }),
    )
    .await;
    act(
        h,
        &format!("{org_base}/groups/{ops}/roles"),
        "er-g-ops-role",
        &serde_json::json!({ "role_id": billing }),
    )
    .await;
    let ida = member(h, base, org, "ida").await;
    act(
        h,
        &format!("{org_base}/groups/{ops}/members"),
        "er-g-ida",
        &serde_json::json!({ "membership_id": ida }),
    )
    .await;
    (henry, ops, ida)
}

/// Raise an access request and have a DIFFERENT principal approve it.
///
/// The fourth source the export can report (issue #145 criterion 4). It needs two principals
/// because the separation rule refuses a self-approval structurally, so the operator token
/// raises and a freshly minted management key decides.
///
async fn raise_and_approve(h: &Harness, base: &str, org: &str, subject: &str) {
    let org_base = format!("{base}/organizations/{org}");
    let request = create(
        h,
        &format!("{org_base}/access-requests"),
        "er-raise",
        &serde_json::json!({
            "subject_id": subject,
            "role_slug": "billing-admin",
            "reason": "quarter close",
        }),
    )
    .await;

    let (key_id, secret) = {
        let (status, _, body) = h
            .post(
                &format!("{base}/keys"),
                "er-approver-key",
                &serde_json::json!({ "display_name": "approver" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "mint the approver key: {body}");
        let created: Value = serde_json::from_str(&body).expect("json");
        (
            created["id"].as_str().expect("id").to_owned(),
            created["secret"].as_str().expect("secret").to_owned(),
        )
    };
    // The scope ids are the two path segments of `base`, which is
    // `/v1/tenants/{tenant}/environments/{environment}`.
    let mut parts = base.split('/').skip(3);
    let tenant = parts.next().expect("tenant segment");
    let environment = parts.nth(1).expect("environment segment");
    sqlx::query(
        "UPDATE management_credentials SET permissions = $1 \
         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(vec!["management.write_organizations".to_owned()])
    .bind(&key_id)
    .bind(tenant)
    .bind(environment)
    .execute(h.db().owner_pool())
    .await
    .expect("grant the approver its permission");

    let (status, _, body) = h
        .post_as(
            &format!("{org_base}/access-requests/{request}/decision"),
            &secret,
            "er-decide",
            &serde_json::json!({ "approve": true, "grant_secs": 3600 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "approve the request: {body}");
}

/// A second organization that works, and is then DISABLED.
///
/// Returns `(id, whether it resolved a grant while it was still active)`. The second half is
/// the control: an organization that never granted anything is empty afterwards for a reason
/// that has nothing to do with the disable.
async fn seed_and_disable_a_second_org(h: &Harness, base: &str) -> (String, bool) {
    let org = create(
        h,
        &format!("{base}/organizations"),
        "er-org-2",
        &serde_json::json!({ "display_name": "Initech" }),
    )
    .await;
    let org_base = format!("{base}/organizations/{org}");
    let role = create(
        h,
        &format!("{org_base}/roles"),
        "er2-role",
        &serde_json::json!({ "slug": "staff", "display_name": "Staff" }),
    )
    .await;
    let (status, _, body) = h
        .put(
            &format!("{org_base}/default-role"),
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert!(status.is_success(), "second org default role: {body}");
    let _member = member(h, base, &org, "gail").await;

    let was_live = !exported_paths(h, &org_base).await.is_empty();

    let (status, _, body) = h
        .post(&format!("{org_base}/disable"), "er2-disable", "")
        .await;
    assert!(status.is_success(), "disable the second org: {status} {body}");
    (org, was_live)
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

/// Take the organization apart in the ways the resolver honours and the feed announces.
///
/// SIX removals, each drawn on a different subject so that no two mask each other: a withdrawn
/// direct grant, a deleted role, a removed membership, a deleted group, a soft-deleted user, a
/// member taken out of a group, and a role taken off a group. Each drops rows from the export
/// through a fence at some level, and each is a way for a fold to go on reporting access that
/// no longer exists. Separate from the build so the build reads as a working organization and
/// this reads as what happens to it.
/// What `disturb` takes away, named so the call site reads as a list of removals.
struct Doomed<'a> {
    alice: &'a str,
    dave: &'a str,
    reports: &'a str,
    role: &'a str,
    group: &'a str,
    frank_user: &'a str,
    finance: &'a str,
    henry: &'a str,
    ops: &'a str,
    billing: &'a str,
}

async fn disturb(h: &Harness, org_base: &str, doomed: &Doomed<'_>) {
    let Doomed {
        alice,
        dave,
        reports,
        role: doomed_role,
        group: doomed_group,
        frank_user,
        finance,
        henry,
        ops,
        billing,
    } = doomed;
    // THE DIVERGENCES, in the order that makes each of them awkward.
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

    // THE USER SOFT-DELETE, which a reviewer reproduced against the first version of this
    // file by adding it: it empties a member's grants in the export through a fence the fold
    // had no arm for, and announces nothing the earlier arms were watching.
    //
    // Soft-deleting the USER leaves `org_memberships` untouched, so `organization.member_added`
    // is never undone and only `user.deleted` says the access is gone.
    let base = org_base
        .split_once("/organizations/")
        .expect("an organization path")
        .0;
    let (status, _, body) = h.delete(&format!("{base}/users/{frank_user}")).await;
    assert!(status.is_success(), "soft-delete the user: {status} {body}");

    // AND THE TWO THE ROUND-1 FIXTURE NEVER REACHED. A reviewer measured both arms as dead
    // code: deleting either from the fold left every assertion green.
    let (status, _, body) = h
        .delete(&format!("{org_base}/groups/{finance}/members/{henry}"))
        .await;
    assert!(status.is_success(), "remove henry from the group: {body}");
    let (status, _, body) = h
        .delete(&format!("{org_base}/groups/{ops}/roles/{billing}"))
        .await;
    assert!(status.is_success(), "unassign the group's role: {body}");

}

/// Every id the scenario mints, so the assertions can name what they are talking about.
struct Fixture {
    henry: String,
    ida: String,
    /// A second organization, disabled after it was working.
    elsewhere: String,
    /// Whether it resolved anything BEFORE the disable.
    elsewhere_was_live: bool,
    erin: String,
    frank: String,
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
    let (elsewhere, elsewhere_was_live) = seed_and_disable_a_second_org(h, base).await;
    let (billing, reports, doomed_role, finance, finance_ap, doomed_group) =
        seed_catalogue(h, &org_base).await;

    let m = seed_members(
        h,
        base,
        org,
        &org_base,
        &billing,
        &reports,
        &finance,
        &finance_ap,
        &doomed_group,
        &doomed_role,
    )
    .await;
    let Members {
        alice,
        bob,
        carol,
        dave,
        erin,
        frank,
        frank_user,
        henry,
        ida,
        ops,
    } = m;

    disturb(
        h,
        &org_base,
        &Doomed {
            alice: &alice,
            dave: &dave,
            reports: &reports,
            role: &doomed_role,
            group: &doomed_group,
            frank_user: &frank_user,
            finance: &finance,
            henry: &henry,
            ops: &ops,
            billing: &billing,
        },
    )
    .await;

    Fixture {
        henry,
        ida,
        elsewhere,
        elsewhere_was_live,
        erin,
        frank,
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

/// The disabled organization, compared on its own.
///
/// Separate because the export is scoped to ONE organization: disabling the one under test
/// would empty both sides at once, which every assertion in the main comparison would happily
/// accept.
async fn assert_the_disabled_organization_is_empty_on_both_sides(
    h: &Harness,
    base: &str,
    f: &Fixture,
    replay: &Replay,
    slugs: &BTreeMap<String, String>,
    now_unix_ms: i64,
) {
    // THE DISABLED ORGANIZATION, compared separately because the export is scoped to ONE
    // organization and disabling the one under test would empty both sides at once -- which
    // every assertion above would happily accept.
    //
    let elsewhere_base = format!("{base}/organizations/{}", f.elsewhere);
    // A second organization with its own member and its own default role, then disabled. The
    // resolver seeds `membership` only under `o.state = 'active'`, so it resolves nothing and
    // the export carries one `none` row per member; the fold has to reach the same answer from
    // `organization.state_changed` alone, because nothing else on the feed says the grants are
    // gone. LIVE FIRST, so the emptiness is the disable and not an organization that never
    // worked.
    // ITS OWN ROLE CATALOGUE, merged in. Without it `staff` has no slug in the map, `push`
    // bails, and the fold reports nothing for this organization whatever the disable did --
    // measured: the mutant that ignores `organization.state_changed` entirely survived until
    // this line existed. The lookup was doing the fence's job again, exactly as it did for the
    // deleted role.
    let mut all_slugs = slugs.clone();
    all_slugs.extend(api_role_slugs(h, &elsewhere_base).await);
    let rebuilt_elsewhere = replay.resolve(&f.elsewhere, &all_slugs, now_unix_ms);
    assert!(
        rebuilt_elsewhere.is_empty(),
        "the fold still reports grants for a DISABLED organization: {rebuilt_elsewhere:?}"
    );
    assert!(
        exported_paths(h, &elsewhere_base).await.is_empty(),
        "the export still reports grants for a disabled organization, so the fold agreeing \
         that it has none would prove nothing"
    );
    // THE CONTROL, ON THE FOLD'S SIDE. `elsewhere_was_live` says the EXPORT answered before
    // the disable, which is a fact about the server: a fold that never saw the second
    // organization at all -- no membership, no role, no default -- satisfies the emptiness
    // above while that control still passes, so it was matched on the wrong side. What has to
    // be true is that the fold KNOWS this organization and would have reported it but for the
    // disable.
    assert!(
        f.elsewhere_was_live,
        "the second organization never resolved a grant even before it was disabled"
    );
    assert!(
        replay
            .memberships
            .values()
            .any(|owner| *owner == f.elsewhere),
        "the fold never saw a membership of the second organization, so it would report \
         nothing for it however the disable had gone"
    );
    assert!(
        replay.default_role.contains_key(&f.elsewhere),
        "the fold never saw the second organization's default role, so the emptiness above is \
         ignorance rather than the disable"
    );

}

/// Every removal actually reached the snapshot.
///
/// Every assertion in the comparison above is satisfied by a fixture in which none of the
/// removals landed, which is precisely how #1222 passed while proving nothing. These name each
/// one, so a fixture that stopped reaching a case fails here rather than going quiet.
fn assert_every_removal_landed(rebuilt: &BTreeSet<GrantPath>, f: &Fixture) {
    let slugs_of = |membership: &str| {
        rebuilt
            .iter()
            .filter(|path| path.membership_id == membership)
            .map(|path| path.role_slug.clone())
            .collect::<BTreeSet<_>>()
    };
    // AND THE DIVERGENCES ACTUALLY HAPPENED. Every assertion above is satisfied by a fixture
    // in which none of the four removals landed, which is precisely how the first attempt at
    // this passed while proving nothing.
    assert!(
        !slugs_of(&f.alice).contains("reports-reader"),
        "the withdrawn direct grant is still in the snapshot"
    );
    assert!(
        !slugs_of(&f.carol).contains("temp-admin"),
        "the deleted role is still granted in the snapshot"
    );
    assert!(
        slugs_of(&f.dave).is_empty(),
        "the removed membership still holds roles in the snapshot"
    );
    assert!(
        slugs_of(&f.bob).contains("reports-reader"),
        "the role held through the ANCESTOR group is missing, so the closure was not folded"
    );
    assert!(
        slugs_of(&f.alice).contains("billing-admin") && slugs_of(&f.alice).contains("member"),
        "alice should still hold her direct grant and the organization default"
    );
    // THE FOURTH SOURCE reached the comparison. Without this the export and the fold could
    // both be missing it and agree, which is how a source goes unmeasured.
    assert!(
        rebuilt
            .iter()
            .any(|path| path.membership_id == f.carol && path.source == "time_boxed"),
        "the live time-boxed grant is not in the snapshot, so the export's fourth source is \
         outside everything this test compares"
    );
    assert!(
        slugs_of(&f.henry) == ["member".to_owned()].into_iter().collect(),
        "henry was removed from the GROUP, not from the organization, so he should have lost \
         the inherited role and kept the default: {:?}",
        slugs_of(&f.henry)
    );
    assert!(
        slugs_of(&f.ida) == ["member".to_owned()].into_iter().collect(),
        "ida is still in her group and the group's ROLE was unassigned, so she should have \
         lost it and kept the default: {:?}",
        slugs_of(&f.ida)
    );
    assert!(
        slugs_of(&f.frank).is_empty(),
        "the member whose USER was soft-deleted still holds roles in the snapshot. Nothing on \
         the feed undoes his membership -- `user.deleted` is the only announcement -- so a \
         fold without that arm keeps reporting access the product already revoked"
    );
    assert!(
        slugs_of(&f.erin).contains("member")
            && !slugs_of(&f.erin).contains("billing-admin"),
        "erin was only ever in the DELETED group, so she should keep the default and lose the \
         role that group held"
    );
}

/// A grant whose deadline has passed resolves to nothing.
///
/// A UNIT TEST over the fold, and not another case in the scenario above, because the scenario
/// cannot reach it: an approval's duration is bounded below by the API and the test would have
/// to WAIT for it. Measured, that gap was real -- removing the deadline comparison from
/// `resolve` left every assertion in the scenario green, because its one grant runs for an
/// hour and is live at every instant the test observes.
///
/// The resolver's fourth arm requires `agr.granted_until > $6`, so a grant stops granting when
/// a clock passes rather than when anybody writes a row. That is the whole reason a consumer
/// cannot treat this source like the other three: there is no event to wait for.
#[test]
fn an_expired_time_boxed_grant_resolves_to_nothing() {
    let mut replay = Replay::default();
    replay.memberships.insert("omb_1".to_owned(), "org_1".to_owned());
    replay
        .membership_subject
        .insert("omb_1".to_owned(), "usr_1".to_owned());
    replay.roles.insert("rol_1".to_owned(), "org_1".to_owned());
    let slugs: BTreeMap<String, String> =
        [("rol_1".to_owned(), "billing-admin".to_owned())].into_iter().collect();

    let grant = |granted_until_unix_ms| TimeBoxed {
        organization: "org_1".to_owned(),
        subject: "usr_1".to_owned(),
        role_slug: "billing-admin".to_owned(),
        granted_until_unix_ms,
    };
    let now = 1_000_000_i64;

    // LIVE FIRST: without this the emptiness below is satisfied by a fold that resolves no
    // time-boxed grant under any circumstances.
    replay.time_boxed.insert(grant(now + 1));
    assert_eq!(
        replay.resolve("org_1", &slugs, now).len(),
        1,
        "a grant one millisecond from its deadline still grants"
    );

    replay.time_boxed.clear();
    replay.time_boxed.insert(grant(now));
    assert!(
        replay.resolve("org_1", &slugs, now).is_empty(),
        "a grant AT its deadline has stopped granting: the resolver's bound is `>`, so the \
         two are half-open at the same instant and a consumer that rounded the other way \
         would report an elevation that has ended"
    );
    replay.time_boxed.clear();
    replay.time_boxed.insert(grant(now - 1));
    assert!(
        replay.resolve("org_1", &slugs, now).is_empty(),
        "a lapsed grant still resolves"
    );
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

    // THE FOLD, waiting for the last of those to reach the feed.
    // The SENTINEL is the last thing `disturb` does, so seeing it means the whole scenario has
    // reached the feed.
    let (replay, pages_read) = fold_feed(&h, &tenant, &environment, "user.deleted").await;
    assert!(
        pages_read > 1,
        "the fold read the whole feed in {pages_read} page(s), so nothing here exercised the \
         cursor and `limit={PAGE}` is no longer smaller than the scenario"
    );
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
        !replay.memberships.contains_key(&f.dave),
        "the fold did not see `organization.member_removed`; the removed member is still live"
    );
    // AND THE CONTROLS, so the three above are not satisfied by a fold that saw nothing at all.
    assert!(
        replay.roles.contains_key(&billing) && replay.groups.contains_key(&finance),
        "the fold lost rows it was never told to drop, so the absences above prove nothing"
    );

    // THE TREE THE FOLD BUILT must match the one the API reports. Not a redundant check: the
    // parent edge only reaches the feed because the create announces it, and if that
    // announcement were dropped the fold would silently attach every nested group to the root
    // and still agree with the export for any role granted to a LEAF.
    let api_parents = api_group_parents(&h, &org_base).await;
    for (group, parent) in &api_parents {
        assert_eq!(
            replay.group_parents.get(group).cloned().flatten().as_ref(),
            parent.as_ref(),
            "the feed and the API disagree about the parent of {group}"
        );
    }
    let slugs = api_role_slugs(&h, &org_base).await;
    // THE INSTANT the fold judges deadlines against, taken once. The export resolves against
    // the server's clock a moment earlier, so a grant whose deadline fell between the two
    // would make the two sides disagree for a reason that is not a defect; the fixture's grant
    // runs for an hour, so the window is not one this test can land in.
    let now_unix_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_millis(),
    )
    .expect("fits i64");
    let rebuilt = replay.resolve(&org, &slugs, now_unix_ms);
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

    assert_the_disabled_organization_is_empty_on_both_sides(
        &h, &base, &f, &replay, &slugs, now_unix_ms,
    )
    .await;

    assert_every_removal_landed(&rebuilt, &f);
}
