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
use ironauth_admin::scim_push_events::Collection;
use ironauth_admin::scim_push_transport::{
    ScimRequest, ScimResponse, ScimTransport, ScimTransportError,
};
use ironauth_admin::scim_push_worker::{
    Pass, SourceError, SubjectSource, WorkerError, run_backfill_pass,
};
use ironauth_env::Env;
use ironauth_scim::downstream::Downstream;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewAdminUser, NewMembership, NewOrgGroup, NewOrgGroupMember,
    NewScimPushConnection, NewUserTraits, ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId,
    OrgGroupMemberId, OrgMembershipId, OrganizationId, ScimDeletionPolicy, ScimPushConnection,
    ScimPushConnectionId, ScimWriteMode, Scope, TraitWriteVisibility, UserId, UserState,
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

    /// A SECOND organization in the same environment, for the confinement tests.
    ///
    /// The same environment on purpose: the event feed is environment-wide, so the interesting
    /// neighbour is one whose events this connection will actually read.
    async fn sibling(&self, display_name: &str) -> OrganizationId {
        let id = OrganizationId::generate(&self.env, &self.scope);
        self.db
            .control_store()
            .management()
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .organizations(self.scope)
            .create(&self.env, &id, now_micros(&self.env), display_name, None)
            .await
            .expect("create the sibling organization");
        id
    }

    /// An active user bound into `organization` rather than into this one.
    async fn member_of(&self, organization: &OrganizationId, identifier: &str) -> UserId {
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
                    id: None,
                    identifier,
                    password_hash: Some(PASSWORD_HASH),
                    claims_json: None,
                    external_id: None,
                    state: UserState::Active,
                    foreign_password_hash: None,
                    foreign_password_algo: None,
                    traits: None,
                },
                now_micros(&self.env),
                None,
            )
            .await
            .expect("create active user");
        let membership_id = OrgMembershipId::generate(&self.env, &self.scope);
        self.db
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
                    organization_id: organization,
                    user_id: &user,
                    metadata: None,
                },
                now_micros(&self.env),
                None,
            )
            .await
            .expect("bind user into the sibling organization");
        user
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
    // A MEMBER REFERENCE IS THE DOWNSTREAM'S OWN ID FOR THAT PERSON, not IronAuth's. RFC 7643
    // section 4.2 says `members[].value` identifies the member AT THIS SERVER, so a reference
    // carrying a foreign id is one no downstream can resolve: the group stores and the
    // membership means nothing.
    //
    // The expected values are DERIVED from what the downstream stored for each person, so a
    // change to how either side mints ids cannot make this assertion quietly wrong.
    let downstream_users = downstream.users();
    let id_of = |subject: &UserId| -> String {
        downstream_users
            .values()
            .find(|u| u["externalId"].as_str() == Some(subject.to_string().as_str()))
            .and_then(|u| u["id"].as_str())
            .unwrap_or_else(|| {
                panic!("{subject} was never provisioned, so it has no downstream id")
            })
            .to_owned()
    };
    let (ada_id, grace_id) = (id_of(&ada), id_of(&grace));
    assert!(
        members.contains(&ada_id.as_str()) && members.contains(&grace_id.as_str()),
        "the members are not the downstream ids of the people the group holds: {provisioned}"
    );
    assert!(
        !members.contains(&ada.to_string().as_str()),
        "a member reference carries IronAuth's own id, which no downstream can resolve: \
         {provisioned}"
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

#[tokio::test]
async fn a_person_from_another_organization_is_not_this_connections_subject() {
    // WHY THIS EXISTS, and it was a CROSS-ORGANIZATION LEAK.
    //
    // `admits` returned true without reading anything when the connection had no scope filter --
    // the default the management surface allows -- on the grounds that the connection is attached
    // to one organization and every read is confined to it. That sentence was true of `build`.
    // It was not true of `admits`, which on that path never called `build` and answered true for
    // any string at all.
    //
    // The worker relies on this for confinement and says so: the event feed is ENVIRONMENT-wide,
    // and the fence in `apply_one` can only filter events whose schema NAMES an organization.
    // `user.deleted` names none. So a deletion in organization B reached organization A's
    // connection as an in-scope departure, and A's client sent
    // `GET /Users?filter=externalId eq "<B's user id>"` to A's downstream -- disclosing B's
    // subject id, and on a downstream both organizations point at, deactivating them there.
    let org = Org::start().await;
    let (ours, _) = org.member("ada@globex.example", None).await;
    let neighbour = org.sibling("Initech").await;
    let theirs = org.member_of(&neighbour, "bob@initech.example").await;

    // NO FILTER, which is the configuration the defect needed and the one an operator gets by
    // default.
    let connection = org.connection(&json!({}), None).await;
    let store = org.db.store().scoped(org.scope);
    let record = store
        .scim_push_connections()
        .find_in_org(&org.id, &connection)
        .await
        .expect("read the connection")
        .expect("the connection exists");
    let directory = PushDirectory::new(&store, &record).expect("the filters parse");

    assert!(
        directory
            .in_scope(Collection::User, &ours.to_string())
            .await
            .expect("in_scope answers"),
        "our own member is not in scope, so this connection would provision nobody"
    );
    assert!(
        !directory
            .in_scope(Collection::User, &theirs.to_string())
            .await
            .expect("in_scope answers"),
        "a person who belongs to another organization is in scope for this connection: {theirs}"
    );
    assert!(
        directory
            .resource(Collection::User, &theirs.to_string())
            .await
            .expect("resource answers")
            .is_none(),
        "another organization's person has a body on this connection: {theirs}"
    );
}

#[tokio::test]
async fn a_group_member_the_scope_filter_excludes_is_not_named_in_the_group() {
    // WHY THIS EXISTS. The connection's `user_scope_filter` reached `admits` for a person pushed
    // on their own and never reached a person NAMED INSIDE A GROUP, so the group body handed the
    // downstream the identifier of every member including the ones the operator's filter excludes.
    // The confinement they configured had a hole in exactly the shape of their groups.
    //
    // THE FILTER HAS TO NARROW AFTER THE PERSON IS PROVISIONED, and the first version of this
    // test missed that. A member reference is resolved through the link table, so somebody the
    // filter excluded from the start has no link and is dropped for that reason instead: removing
    // the scope check entirely left the test green. Narrowing an EXISTING connection is the shape
    // where the link is live and the filter is the only thing that can exclude them -- and it is
    // the ordinary operational case, an operator tightening a filter on a running connection.
    let org = Org::start().await;
    let (kept, kept_membership) = org
        .member("kept@globex.example", Some(&json!({ "dept": "eng" })))
        .await;
    let (excluded, excluded_membership) = org
        .member("excluded@globex.example", Some(&json!({ "dept": "sales" })))
        .await;
    let group = org.group("engineering", "Engineering").await;
    org.bind(&group, &kept_membership).await;
    org.bind(&group, &excluded_membership).await;

    // FIRST, with no filter: both people are provisioned and both hold live links.
    let mapping = json!({ "userName": "identifier", "title": "traits.dept" });
    let connection = org.connection(&mapping, None).await;
    let downstream = backfill(&org, &connection, 10).await;
    let users = downstream.users();
    assert_eq!(users.len(), 2, "both were not provisioned: {users:?}");
    let downstream_id = |subject: &UserId| -> String {
        users
            .values()
            .find(|u| u["externalId"].as_str() == Some(subject.to_string().as_str()))
            .and_then(|u| u["id"].as_str())
            .expect("provisioned, so it has a downstream id")
            .to_owned()
    };
    let (kept_id, excluded_id) = (downstream_id(&kept), downstream_id(&excluded));

    let store = org.db.store().scoped(org.scope);
    let before = store
        .scim_push_connections()
        .find_in_org(&org.id, &connection)
        .await
        .expect("read the connection")
        .expect("the connection exists");
    let wide = PushDirectory::new(&store, &before).expect("the filters parse");
    let group_body = wide
        .resource(Collection::Group, &group.to_string())
        .await
        .expect("the group builds")
        .expect("the group exists");
    let wide_members = member_values(&group_body);
    assert!(
        wide_members.contains(&kept_id) && wide_members.contains(&excluded_id),
        "the unfiltered connection did not name both members, so narrowing proves nothing: \
         {group_body}"
    );

    // NOW THE OPERATOR NARROWS IT. Both links are still live; only the filter changes.
    let narrowed = ScimPushConnection {
        user_scope_filter: Some("title eq \"eng\"".to_owned()),
        ..before
    };
    let directory = PushDirectory::new(&store, &narrowed).expect("the filters parse");
    let group_body = directory
        .resource(Collection::Group, &group.to_string())
        .await
        .expect("the group builds")
        .expect("the group exists");
    let members = member_values(&group_body);
    assert_eq!(
        members,
        vec![kept_id],
        "the group names a member this connection's filter excludes, whose link is still live: \
         {group_body}"
    );
}

/// The `members[].value` references of a SCIM Group body.
fn member_values(group: &Value) -> Vec<String> {
    group["members"]
        .as_array()
        .expect("members is an array")
        .iter()
        .filter_map(|m| m["value"].as_str().map(ToOwned::to_owned))
        .collect()
}

#[tokio::test]
async fn a_store_fault_reading_a_person_is_reported_rather_than_read_as_a_departure() {
    // WHY THIS EXISTS. `build_user` opened with `let Ok(user) = ... else { return Ok(None) }`,
    // which put a connection reset, a statement timeout, a failover and a missing master key in
    // the same arm as a deleted user. `None` is what the tail reads as "this person is gone":
    // `scope_decision` turns it into a Withdraw and the connection deactivates them downstream.
    // One database hiccup during a pass would have deprovisioned the whole page.
    //
    // THE FAULT IS INJECTED, not simulated. Revoking the app role's SELECT makes the read fail
    // with SQLSTATE 42501, which is a `StoreError::Database` and not a `NotFound` -- the exact
    // distinction the arm has to make. A test that only deleted the row would exercise the arm
    // that already worked.
    let org = Org::start().await;
    let (ada, _) = org.member("ada@globex.example", None).await;
    let connection = org.connection(&json!({}), None).await;
    let store = org.db.store().scoped(org.scope);
    let record = store
        .scim_push_connections()
        .find_in_org(&org.id, &connection)
        .await
        .expect("read the connection")
        .expect("the connection exists");
    let directory = PushDirectory::new(&store, &record).expect("the filters parse");

    // The control: the same call answers a body while the read works.
    assert!(
        directory
            .resource(Collection::User, &ada.to_string())
            .await
            .expect("resource answers")
            .is_some(),
        "the fixture cannot read this person at all, so the fault case proves nothing"
    );

    sqlx::query("REVOKE SELECT ON users FROM ironauth_app")
        .execute(org.db.owner_pool())
        .await
        .expect("revoke the read");

    let faulted = directory.resource(Collection::User, &ada.to_string()).await;

    sqlx::query("GRANT SELECT ON users TO ironauth_app")
        .execute(org.db.owner_pool())
        .await
        .expect("restore the read");

    match faulted {
        Err(SourceError::Retryable(_)) => {}
        Ok(None) => panic!(
            "a store fault was reported as an absence, which the tail turns into a deprovision"
        ),
        other => panic!("a store fault must be retryable, not {other:?}"),
    }

    // AND THE CONTROL AGAIN, so a permanently broken fixture cannot pass the assertion above.
    assert!(
        directory
            .resource(Collection::User, &ada.to_string())
            .await
            .expect("resource answers once the read is restored")
            .is_some(),
        "the grant was not restored, so the assertion above proved nothing"
    );
}

#[tokio::test]
async fn a_mapping_the_source_will_always_refuse_is_permanent_rather_than_a_wedge() {
    // WHY THIS EXISTS. `SubjectSource` returned `String` and both call sites wrapped it in
    // `WorkerError::Retryable`. A source refusal that can never succeed -- a mapping targeting a
    // reserved attribute, a group too large for one body -- therefore stopped the pass without
    // checkpointing: the connection re-read the same page, hit the same subject, and paused with
    // a doubling backoff for ever, with everything behind it undelivered. It is the same wedge
    // the per-subject refusal arm exists to close, one layer down where that arm could not see it.
    //
    // The mapping is written STRAIGHT TO THE COLUMN because the management surface refuses this
    // one at write time. That is the right place for it to be refused and it is not the only way
    // such a mapping can arrive: a mapping stored before a rule existed, or a reserved attribute
    // added later, reaches the worker the same way.
    let org = Org::start().await;
    org.member("ada@globex.example", None).await;
    let connection = org.connection(&json!({}), None).await;
    sqlx::query("UPDATE scim_push_connections SET attribute_mapping = $1::jsonb WHERE id = $2")
        .bind(r#"{"active":"traits.enabled"}"#)
        .bind(connection.to_string())
        .execute(org.db.owner_pool())
        .await
        .expect("store a mapping the surface would refuse");

    let store = org.db.store().scoped(org.scope);
    let record = store
        .scim_push_connections()
        .find_in_org(&org.id, &connection)
        .await
        .expect("read the connection")
        .expect("the connection exists");
    let directory = PushDirectory::new(&store, &record).expect("the filters parse");
    let client = ScimPushClient::new(
        FixtureTransport {
            downstream: Downstream::new(TOKEN),
        },
        BASE,
        TOKEN,
        WriteMode::Patch,
    );
    let outcome = run_backfill_pass(
        &store,
        Pass {
            connection_id: &connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 10,
            scope: org.scope,
            now_unix_micros: now_micros(&org.env),
            organization_id: org.id.to_string(),
        },
    )
    .await;

    // PERMANENT, not retryable. Retryable is what pauses the connection and re-reads the page.
    match outcome {
        Err(WorkerError::Permanent(why)) => assert!(
            why.contains("mapping"),
            "the refusal does not say what an operator has to fix: {why}"
        ),
        other => panic!(
            "a mapping this source will refuse every time was not reported as permanent: {other:?}"
        ),
    }
}
