// SPDX-License-Identifier: MIT OR Apache-2.0

//! The production directory an outbound connection pushes (issue #137, criterion 1).
//!
//! # Why this file exists
//!
//! Criterion 1 asks for writes reaching a downstream "with attribute mapping applied". Every part
//! of that shipped and none of it was joined up: `scim_push_mapping` had no caller outside its own
//! test, `SubjectSource` had one implementor and it was a test double that hands the worker
//! pre-built SCIM bodies, and `run_due_connections` had no caller in `src`. Deleting the body of
//! the mapper and replacing it with `unimplemented!()` left the whole worker suite green.
//!
//! So this file drives the worker against the REAL store: real users, real memberships, real
//! groups, a real attribute mapping, and the reference downstream at the other end. It is the
//! only place where a mapping the operator configured is observed on a resource the downstream
//! actually received.

#![cfg(feature = "testing")]

use std::future::Future;

use axum::body::Body;
use axum::http::Request;
use ironauth_admin::scim_push_client::{DeletionPolicy, ScimPushClient, WriteMode};
use ironauth_admin::scim_push_directory::PushDirectory;
use ironauth_admin::scim_push_transport::{
    ScimRequest, ScimResponse, ScimTransport, ScimTransportError,
};
use ironauth_admin::scim_push_worker::{Pass, run_backfill_pass};
use ironauth_env::Env;
use ironauth_scim::downstream::Downstream;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewAdminUser, NewMembership, NewOrgGroup, NewOrgGroupMember,
    NewScimPushConnection, NewUserTraits, ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId,
    OrgGroupMemberId, OrgMembershipId, OrganizationId, ScimDeletionPolicy, ScimPushConnectionId,
    ScimWriteMode, Scope, TraitWriteVisibility, UserId, UserState,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "downstream-bearer-token";
const BASE: &str = "https://downstream.example/scim/v2";
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

fn now_micros(_env: &Env) -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Carries a request into the fixture's router.
#[derive(Clone)]
struct FixtureTransport {
    downstream: Downstream,
}

impl ScimTransport for FixtureTransport {
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        let downstream = self.downstream.clone();
        let base_path = base_url
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').map(|i| rest[i..].to_owned()))
            .unwrap_or_default();
        let mut uri = format!("{}{}", base_path.trim_end_matches('/'), request.path);
        if let Some(filter) = &request.filter {
            uri.push_str("?filter=");
            for byte in filter.as_bytes() {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        uri.push(*byte as char);
                    }
                    _ => {
                        use std::fmt::Write as _;
                        let _ = write!(uri, "%{byte:02X}");
                    }
                }
            }
        }
        let authorization = format!("Bearer {bearer}");
        async move {
            let builder = Request::builder()
                .method(request.method)
                .uri(uri)
                .header("authorization", authorization);
            let http_request = match request.body {
                Some(body) => builder
                    .header("content-type", "application/scim+json")
                    .body(Body::from(body.to_string())),
                None => builder.body(Body::empty()),
            }
            .map_err(|_| ScimTransportError::Transport)?;
            let response = downstream
                .router()
                .oneshot(http_request)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            let body = serde_json::from_slice::<Value>(&bytes).ok();
            Ok(ScimResponse { status, body })
        }
    }
}

/// A real organization with real people and groups in it.
struct Org {
    db: TestDatabase,
    env: Env,
    scope: Scope,
    id: OrganizationId,
}

impl Org {
    async fn start() -> Self {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let id = OrganizationId::generate(&env, &scope);
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .create(&env, &id, now_micros(&env), "Globex", None)
            .await
            .expect("create organization");
        Self { db, env, scope, id }
    }

    /// An active user, bound into the organization, with `traits`.
    async fn member(&self, identifier: &str, traits: Option<&Value>) -> (UserId, OrgMembershipId) {
        self.member_with_id(None, identifier, traits).await
    }

    /// The same, on an id the caller chose, so a test can fix the enumeration order.
    async fn member_with_id(
        &self,
        id: Option<&UserId>,
        identifier: &str,
        traits: Option<&Value>,
    ) -> (UserId, OrgMembershipId) {
        let traits_json = traits.map(ToString::to_string);
        let user = self
            .db
            .control_store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .users()
            .admin_create(
                &self.env,
                NewAdminUser {
                    id,
                    identifier,
                    password_hash: Some(PASSWORD_HASH),
                    claims_json: None,
                    external_id: None,
                    state: UserState::Active,
                    foreign_password_hash: None,
                    foreign_password_algo: None,
                    traits: traits_json.as_deref().map(|traits_json| NewUserTraits {
                        traits_json,
                        schema_version: None,
                        visibility: TraitWriteVisibility::Admin,
                    }),
                },
                now_micros(&self.env),
                None,
            )
            .await
            .expect("create active user");
        let membership_id = OrgMembershipId::generate(&self.env, &self.scope);
        let membership = self
            .db
            .control_store()
            .management()
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .org_memberships(self.scope)
            .create(
                &self.env,
                NewMembership {
                    id: &membership_id,
                    organization_id: &self.id,
                    user_id: &user,
                    metadata: None,
                },
                now_micros(&self.env),
                None,
            )
            .await
            .expect("bind user into organization");
        (user, membership.id)
    }

    async fn group(&self, slug: &str, display_name: &str) -> OrgGroupId {
        let id = OrgGroupId::generate(&self.env, &self.scope);
        self.db
            .control_store()
            .management()
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .org_groups(self.scope)
            .create(
                &self.env,
                NewOrgGroup {
                    id: &id,
                    organization_id: &self.id,
                    parent_id: None,
                    slug,
                    display_name,
                    metadata: None,
                },
                now_micros(&self.env),
                ORG_GROUP_MAX_DEPTH_CEILING,
                None,
            )
            .await
            .expect("create group");
        id
    }

    async fn bind(&self, group: &OrgGroupId, membership: &OrgMembershipId) {
        let id = OrgGroupMemberId::generate(&self.env, &self.scope);
        self.db
            .control_store()
            .management()
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .org_group_members(self.scope)
            .add(
                &self.env,
                NewOrgGroupMember {
                    id: &id,
                    organization_id: &self.id,
                    group_id: group,
                    membership_id: membership,
                    source_scim_connection_id: None,
                },
                now_micros(&self.env),
                None,
            )
            .await
            .expect("bind member into group");
    }

    /// A push connection with the given mapping and user filter, already enumerating.
    async fn connection(
        &self,
        attribute_mapping: &Value,
        user_scope_filter: Option<&str>,
    ) -> ScimPushConnectionId {
        let id = ScimPushConnectionId::generate(&self.env, &self.scope);
        self.db
            .control_store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .scim_push_connections()
            .create(
                &self.env,
                NewScimPushConnection {
                    id: &id,
                    organization_id: &self.id,
                    display_name: "Okta production",
                    base_url: BASE,
                    credential_secret_name: "downstream_token",
                    attribute_mapping,
                    user_scope_filter,
                    group_scope_filter: None,
                    write_mode: ScimWriteMode::Patch,
                    deletion_policy: ScimDeletionPolicy::Deactivate,
                },
                None,
                None,
            )
            .await
            .expect("create the push connection");
        self.db
            .store()
            .scoped(self.scope)
            .scim_push_sync_state()
            .begin_backfill(&id, Some(0))
            .await
            .expect("begin the backfill");
        id
    }
}

/// Run the backfill to completion against a real directory, returning what the downstream got.
async fn backfill(org: &Org, connection: &ScimPushConnectionId, limit: i64) -> Downstream {
    let downstream = Downstream::new(TOKEN);
    let store = org.db.store().scoped(org.scope);
    let record = store
        .scim_push_connections()
        .find_in_org(&org.id, connection)
        .await
        .expect("read the connection")
        .expect("the connection exists");
    let directory = PushDirectory::new(&store, &record).expect("the filters parse");
    let client = ScimPushClient::new(
        FixtureTransport {
            downstream: downstream.clone(),
        },
        BASE,
        TOKEN,
        WriteMode::Patch,
    );
    for _ in 0..40 {
        run_backfill_pass(
            &store,
            Pass {
                connection_id: connection,
                client: &client,
                subjects: &directory,
                deletion_policy: DeletionPolicy::Deactivate,
                limit,
                scope: org.scope,
                now_unix_micros: now_micros(&org.env),
                organization_id: org.id.to_string(),
            },
        )
        .await
        .expect("a backfill pass");
        let state = store
            .scim_push_sync_state()
            .get(connection)
            .await
            .expect("get")
            .expect("state");
        if state.backfill_state.is_done() {
            return downstream;
        }
    }
    panic!("the backfill did not finish");
}

#[tokio::test]
async fn the_operators_mapping_is_what_the_downstream_receives() {
    // THE COMPOSITION CRITERION 1 ASKS FOR. Everything below is configured the way an operator
    // configures it -- a trait on a person, a mapping on the connection -- and the assertion is
    // on the body the downstream actually stored. Replace `resource_for`'s body with
    // `unimplemented!()` and this is the test that stops.
    let org = Org::start().await;
    let (user, _) = org
        .member(
            "ada@globex.example",
            Some(&json!({ "given_name": "Ada", "department": "engineering" })),
        )
        .await;
    let connection = org
        .connection(
            &json!({
                "userName": "identifier",
                "name.givenName": "traits.given_name",
                "title": "traits.department",
            }),
            None,
        )
        .await;

    let downstream = backfill(&org, &connection, 10).await;
    let users = downstream.users();
    assert_eq!(users.len(), 1, "the person was not provisioned: {users:?}");
    let provisioned = users.values().next().expect("one user");

    assert_eq!(
        provisioned["userName"].as_str(),
        Some("ada@globex.example"),
        "the mapping did not reach the downstream: {provisioned}"
    );
    // A NESTED PATH, because a flat one would pass against a mapper that ignored the dot.
    assert_eq!(
        provisioned["name"]["givenName"].as_str(),
        Some("Ada"),
        "a nested mapped attribute did not arrive: {provisioned}"
    );
    assert_eq!(
        provisioned["title"].as_str(),
        Some("engineering"),
        "a second mapped attribute did not arrive: {provisioned}"
    );
    // AND THE PROTOCOL'S OWN ATTRIBUTES, which the mapping may not set.
    assert_eq!(
        provisioned["externalId"].as_str(),
        Some(user.to_string().as_str()),
        "the externalId is not the subject id the worker addresses: {provisioned}"
    );
    assert_eq!(
        provisioned["active"].as_bool(),
        Some(true),
        "an active member arrived inactive: {provisioned}"
    );
}

#[tokio::test]
async fn a_group_carries_its_name_and_its_members_with_no_mapping_configured() {
    // THE DEFAULT CONNECTION. `displayName` is REQUIRED of a Group by RFC 7643 section 4.2, and
    // leaving it to the operator's mapping meant a connection created without one built a body
    // the downstream refuses on that very attribute. `members` is the same: a group that syncs
    // without them is an empty group, and the downstream would enforce access for a membership
    // IronAuth does not have.
    let org = Org::start().await;
    let (ada, ada_membership) = org.member("ada@globex.example", None).await;
    let (grace, grace_membership) = org.member("grace@globex.example", None).await;
    let group = org.group("engineering", "Engineering").await;
    org.bind(&group, &ada_membership).await;
    org.bind(&group, &grace_membership).await;

    // NO MAPPING AT ALL, which is what makes this about the default rather than about config.
    let connection = org.connection(&json!({}), None).await;
    let downstream = backfill(&org, &connection, 10).await;

    let groups = downstream.groups();
    assert_eq!(groups.len(), 1, "the group was not provisioned: {groups:?}");
    let provisioned = groups.values().next().expect("one group");
    assert_eq!(
        provisioned["displayName"].as_str(),
        Some("Engineering"),
        "a group arrived without the attribute its schema requires: {provisioned}"
    );
    let members: Vec<&str> = provisioned["members"]
        .as_array()
        .expect("members is an array")
        .iter()
        .filter_map(|m| m["value"].as_str())
        .collect();
    assert_eq!(
        members.len(),
        2,
        "the group arrived short of members: {provisioned}"
    );
    assert!(
        members.contains(&ada.to_string().as_str())
            && members.contains(&grace.to_string().as_str()),
        "the members are not the people the group holds: {provisioned}"
    );
    // AND NO `active`, which RFC 7643 section 4.2 gives Group no room for and which the client's
    // deactivate refusal reads.
    assert!(
        provisioned.get("active").is_none(),
        "a Group arrived carrying `active`: {provisioned}"
    );
}

#[tokio::test]
async fn a_page_of_people_the_filter_excludes_does_not_end_the_enumeration() {
    // WHY THIS EXISTS. The `SubjectSource` contract said `enumerate` returns IN-SCOPE ids, and an
    // empty page ends the collection. A source that honestly filtered a page to nothing would
    // announce the enumeration was finished with the rest of the directory unread, and everybody
    // after that page would be skipped for good -- the one failure the contract's own doc says
    // must not happen.
    //
    // Nothing caught it because the only implementor was a test double that filtered a whole
    // in-memory map and THEN took a page, so it could always fill one. A keyset read over a table
    // cannot. Scope is decided per subject now.
    //
    // THE ADMITTED PERSON MUST SORT LAST, or the first page is in scope and the defect never
    // fires. Two earlier fixtures got this wrong in two different ways and both are worth naming.
    //
    // Creation order does not decide it: user ids are minted from real entropy, and assuming the
    // order made the test pass by luck -- restoring the filtering to `enumerate` left it green.
    //
    // Neither does sorting the ids in Rust. The enumeration is `ORDER BY user_id` in Postgres,
    // under the database's collation, and a byte-wise sort here is a DIFFERENT order: an id
    // alphabet with `-` and `_` in it collates differently under a locale that weighs punctuation
    // below letters. That fixture failed about one run in three.
    //
    // So the order is READ BACK from the database that will do the enumerating, and the filter is
    // written to admit whoever it puts last.
    let org = Org::start().await;
    for n in 0..4 {
        org.member(&format!("person{n}@globex.example"), None).await;
    }

    let store = org.db.store().scoped(org.scope);
    let order = store
        .org_memberships()
        .user_ids_for_org_after(&org.id, None, 10)
        .await
        .expect("the enumeration order");
    assert_eq!(order.len(), 4, "the fixture did not seed four people");
    let keeper = store
        .users()
        .parse_id(order.last().expect("four people"))
        .expect("a user id the enumeration returned");
    let keeper_identifier = store
        .users()
        .get(&keeper)
        .await
        .expect("read the last person")
        .identifier;

    let connection = org
        .connection(
            &json!({ "userName": "identifier" }),
            Some(&format!("userName eq \"{keeper_identifier}\"")),
        )
        .await;

    // A PAGE OF ONE, so the three pages before the keeper are each a page with nobody in scope.
    // Under the old contract the first of them ended the enumeration.
    let downstream = backfill(&org, &connection, 1).await;
    let users = downstream.users();
    assert_eq!(
        users.len(),
        1,
        "the filter admitted the wrong number of people: {users:?}"
    );
    assert_eq!(
        users.values().next().expect("one user")["externalId"].as_str(),
        Some(keeper.to_string().as_str()),
        "the enumeration stopped at the first excluded page, so the one in-scope person, who \
         sorts last, was never provisioned: {users:?}"
    );
}
