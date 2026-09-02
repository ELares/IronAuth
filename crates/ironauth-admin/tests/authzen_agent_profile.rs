// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `AuthZEN` AGENT TOOL PROFILE (issue #133, PROTOTYPE): may this agent call this tool?
//!
//! # What makes this a different question from the two subject types next door
//!
//! A user or a service account HOLDS permissions, and the PDP answers by looking them up. An
//! agent does not: it acts FOR a person, with a narrower set of tools than that person could
//! reach. So the decision is an INTERSECTION, and every test here is written to fail if either
//! half is dropped:
//!
//! - drop the DECLARED-TOOL half and an agent can call every tool its human could;
//! - drop the LINKED-USER half and an agent outlives the revocation of the person it acts for.
//!
//! That shape is why the fixture always seeds an agent whose declared set and whose human's
//! permissions DISAGREE. A fixture where they agreed would satisfy either half alone.
//!
//! # And why the flag matters more here than for the other prototypes
//!
//! This one adds a subject TYPE to an endpoint operators already run in production. Shipping it
//! unflagged would silently widen a live authorization surface, so the default is not "the
//! endpoint refuses an agent" but "the subject type has no meaning here", which is the same
//! answer the endpoint gave before this existed.
//!
//! Over a real database (`DATABASE_URL`).

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

/// The tool the agent DECLARES and its human is permitted for: the allow.
///
/// The permission a tool maps to is `tool.{tool}.{action}`, PER TOOL. The first version of the
/// profile joined `{resource.type}.{action}`, which for a profile that requires the type to be
/// `tool` is the constant `tool.call` for every tool there is -- so the human's half could not
/// tell `deploy` from `destroy`, only the declared set could, and the middle row of this
/// fixture was not expressible. That is what made the whole intersection an intersection with a
/// constant.
const DECLARED_AND_PERMITTED: &str = "deploy";
/// DECLARED by the agent, and its human holds no permission for it.
const DECLARED_NOT_PERMITTED: &str = "destroy";
/// PERMITTED to the human, and outside the agent's declared set.
const PERMITTED_NOT_DECLARED: &str = "rollback";

struct Fixture {
    tenant: String,
    environment: String,
    organization: String,
    user: String,
    agent: String,
    other_org: String,
    /// The `tool.deploy.call` permission row, created ONCE. Permissions are environment
    /// scoped, so the second organization attaches this same row to its own role rather than
    /// creating a duplicate slug, which the unique index refuses.
    permission: String,
}

impl Fixture {
    /// An organization, a user granted two tool permissions, and an agent declaring two tools
    /// that OVERLAP those permissions in exactly one place.
    async fn build(h: &Harness) -> Self {
        let (tenant, environment) = h.create_tenant("acme", "authzen-agents").await;
        let base = format!("/v1/tenants/{tenant}/environments/{environment}");
        let organization = created(
            h,
            &format!("{base}/organizations"),
            "ap-org",
            &json!({ "display_name": "acme" }),
        )
        .await;
        let other_org = created(
            h,
            &format!("{base}/organizations"),
            "ap-org-other",
            &json!({ "display_name": "other" }),
        )
        .await;
        let user = created(
            h,
            &format!("{base}/users"),
            "ap-user",
            // `identifier`, which is what this surface takes. `email` is not a field it knows,
            // so the create would have failed and the fixture would have panicked before any
            // assertion ran -- the shape that shipped twice in this series already.
            &json!({ "identifier": "agent-operator@example.test" }),
        )
        .await;

        // The HUMAN's ceiling: `tool.deploy` and `tool.rollback`, and deliberately NOT
        // `tool.destroy`.
        let role = created(
            h,
            &format!("{base}/organizations/{organization}/roles"),
            "ap-role",
            &json!({ "slug": "operator", "display_name": "Operator" }),
        )
        .await;
        let mut deploy_permission = String::new();
        for tool in [DECLARED_AND_PERMITTED, PERMITTED_NOT_DECLARED] {
            let permission = created(
                h,
                &format!("{base}/permissions"),
                &format!("ap-perm-{tool}"),
                &json!({ "slug": format!("tool.{tool}.call"), "display_name": tool }),
            )
            .await;
            if tool == DECLARED_AND_PERMITTED {
                deploy_permission.clone_from(&permission);
            }
            let (status, _, body) = h
                .post(
                    &format!("{base}/organizations/{organization}/roles/{role}/permissions"),
                    &format!("ap-attach-{tool}"),
                    &json!({ "permission_id": permission }).to_string(),
                )
                .await;
            assert!(status.is_success(), "attach tool.{tool}: {body}");
        }
        let membership = created(
            h,
            &format!("{base}/organizations/{organization}/memberships"),
            "ap-membership",
            &json!({ "user_id": user }),
        )
        .await;
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/memberships/{membership}/roles"),
                "ap-membership-role",
                &json!({ "role_id": role }).to_string(),
            )
            .await;
        assert!(status.is_success(), "assign the role: {body}");

        // The AGENT's declared set: `deploy` and `destroy`. The overlap with the human is
        // exactly `deploy`, which is what makes every assertion below about the intersection
        // rather than about either half.
        let agent = created(
            h,
            &format!("{base}/organizations/{organization}/agents"),
            "ap-agent",
            &json!({
                "linked_user_id": user,
                "display_name": "deploy bot",
                "tool_scopes": [DECLARED_AND_PERMITTED, DECLARED_NOT_PERMITTED],
            }),
        )
        .await;

        Self {
            tenant,
            environment,
            organization,
            user,
            agent,
            other_org,
            permission: deploy_permission,
        }
    }

    fn base(&self) -> String {
        let (tenant, environment) = (&self.tenant, &self.environment);
        format!("/v1/tenants/{tenant}/environments/{environment}")
    }

    fn ask(&self, org: &str, tool: &str) -> Value {
        json!({
            "subject": { "type": "agent", "id": self.agent },
            "resource": { "type": "tool", "id": tool },
            "action": { "name": "call" },
            "context": { "organization_id": org },
        })
    }

    /// The same question, asked as the HUMAN rather than as the agent.
    ///
    /// The control for the confinement test: it proves the person's grants reach the other
    /// organization, so a denial for the AGENT there is about the agent.
    fn ask_as_user(&self, org: &str) -> Value {
        // THE TOOL RIDES THE TYPE for a `user` subject, because that arm joins
        // `{resource.type}.{action.name}` and does not read `resource.id` at all. So
        // `tool.deploy` + `call` is the same slug the agent arm builds from `tool` + `deploy`
        // + `call`, which is what lets this ask the same question as the human. Asking with
        // type `tool` and id `deploy` would join `tool.call`, a permission nobody grants, and
        // the control would deny for a reason that has nothing to do with the confinement.
        //
        // A resource type carrying a dot is the surface's own idiom: the neighbouring suite
        // asks about `billing.invoice` the same way.
        json!({
            "subject": { "type": "user", "id": self.user },
            "resource": { "type": format!("tool.{DECLARED_AND_PERMITTED}") },
            "action": { "name": "call" },
            "context": { "organization_id": org },
        })
    }

    /// Give the linked user the SAME permission in the other organization.
    async fn grant_in_other_org(&self, h: &Harness) {
        let base = self.base();
        let other = &self.other_org;
        let role = created(
            h,
            &format!("{base}/organizations/{other}/roles"),
            "ap-other-role",
            &json!({ "slug": "operator", "display_name": "Operator" }),
        )
        .await;
        // The permission the fixture ALREADY created. Permissions are environment-scoped
        // (`UNIQUE (tenant_id, environment_id, kind, slug)`), not organization-scoped, so
        // creating the same slug again for the second organization is a 409 and the fixture
        // dies before the assertion it exists for. What differs per organization is the ROLE
        // and the assignment, not the permission.
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{other}/roles/{role}/permissions"),
                "ap-other-attach",
                &json!({ "permission_id": self.permission }).to_string(),
            )
            .await;
        assert!(status.is_success(), "attach in the other org: {body}");
        let membership = created(
            h,
            &format!("{base}/organizations/{other}/memberships"),
            "ap-other-membership",
            &json!({ "user_id": self.user }),
        )
        .await;
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{other}/memberships/{membership}/roles"),
                "ap-other-membership-role",
                &json!({ "role_id": role }).to_string(),
            )
            .await;
        assert!(status.is_success(), "assign in the other org: {body}");
    }

    async fn evaluate(&self, h: &Harness, key: &str, body: &Value) -> bool {
        let (status, _, response) = h
            .post(
                &format!("{}/access/v1/evaluation", self.base()),
                key,
                &body.to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "evaluation: {response}");
        serde_json::from_str::<Value>(&response).expect("json")["decision"]
            .as_bool()
            .expect("decision is a bool")
    }

    async fn refuse(&self, h: &Harness, key: &str, body: &Value) -> (StatusCode, String) {
        let (status, _, response) = h
            .post(
                &format!("{}/access/v1/evaluation", self.base()),
                key,
                &body.to_string(),
            )
            .await;
        (status, response)
    }
}

async fn created(h: &Harness, path: &str, key: &str, body: &Value) -> String {
    let (status, _, response) = h.post(path, key, &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "create at {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("the created row carries an id")
        .to_owned()
}

#[tokio::test]
async fn the_decision_is_the_intersection_of_the_declared_set_and_the_humans_permissions() {
    // THE WHOLE PROFILE, in three asks against one fixture. `deploy` is in both halves and
    // allows; `destroy` is declared and unpermitted; `rollback` is permitted and undeclared.
    // Dropping either half of the check makes exactly one of the two denials become an allow,
    // so neither can be removed without this failing.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    assert!(
        f.evaluate(
            &h,
            "ap-ask-allow",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await,
        "a tool the agent declares AND its human is permitted for is allowed"
    );
    assert!(
        !f.evaluate(
            &h,
            "ap-ask-unpermitted",
            &f.ask(&f.organization, DECLARED_NOT_PERMITTED)
        )
        .await,
        "an agent must not exceed the person it acts for, however it was declared"
    );
    assert!(
        !f.evaluate(
            &h,
            "ap-ask-undeclared",
            &f.ask(&f.organization, PERMITTED_NOT_DECLARED)
        )
        .await,
        "and it must not reach a tool the operator did not declare, however privileged its \
         human is"
    );
}

#[tokio::test]
async fn a_suspended_agent_is_denied_while_its_human_still_holds_the_permission() {
    // #130 criterion 5 draws this split at the token door: a suspended agent obtains no token
    // and stays listable. The PDP has to draw it the same way, or an operator who suspends an
    // agent finds the tool calls still authorized.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    // The control: it allows before the suspension, so the denial below is the STATE and not
    // the fixture.
    assert!(
        f.evaluate(
            &h,
            "ap-before",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await
    );

    let (status, _, body) = h
        .put(
            &format!(
                "{}/organizations/{}/agents/{}/state",
                f.base(),
                f.organization,
                f.agent
            ),
            &json!({ "state": "suspended" }).to_string(),
        )
        .await;
    assert!(status.is_success(), "suspend the agent: {body}");

    assert!(
        !f.evaluate(
            &h,
            "ap-after",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await,
        "a suspended agent authorizes nothing"
    );

    // The name's second clause, asserted rather than implied: the HUMAN is untouched, so what
    // changed is the agent and not a grant that quietly disappeared.
    assert!(
        f.evaluate(&h, "ap-human-unchanged", &f.ask_as_user(&f.organization))
            .await,
        "the person is unchanged, so the denial above is the agent's state"
    );
}

#[tokio::test]
async fn an_agent_of_another_organization_is_denied_rather_than_answered() {
    // The confinement every other read on this surface has. Without it a PEP in one
    // organization could ask about another's agent and get a decision computed from grants it
    // has no business seeing.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    // THE HUMAN IS A MEMBER OF THE OTHER ORGANIZATION TOO, holding the same permission there.
    // Without that, the ask denies through the CEILING -- an empty permission set for a
    // non-member -- and this test passes with the confinement check deleted. The confinement is
    // the only thing that can deny once the human's grants are present on both sides.
    f.grant_in_other_org(&h).await;
    assert!(
        f.evaluate(&h, "ap-control-other-org", &f.ask_as_user(&f.other_org))
            .await,
        "the control: the HUMAN can do this in the other organization, so a denial below is \
         about the agent's confinement and not about the grants"
    );

    assert!(
        !f.evaluate(
            &h,
            "ap-other-org",
            &f.ask(&f.other_org, DECLARED_AND_PERMITTED)
        )
        .await,
        "an agent is decided only in the organization it belongs to"
    );
}

#[tokio::test]
async fn an_agent_that_does_not_exist_is_denied_rather_than_reported_missing() {
    // A PDP answers decisions, not questions about existence. Distinguishing "no such agent"
    // from "not allowed" would tell a caller which agent ids are real.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    // A WELL-FORMED id that names nothing, built by flipping the last character of a real one.
    // `agp_{env}_absent` is not parseable in scope, so it was refused at the parser with a 400
    // and never reached the not-found branch this test is named for -- the documented
    // anti-oracle had no test at all.
    let absent = json!({
        "subject": { "type": "agent", "id": flip_last(&f.agent) },
        "resource": { "type": "tool", "id": DECLARED_AND_PERMITTED },
        "action": { "name": "call" },
        "context": { "organization_id": f.organization },
    });
    let (status, response) = f.refuse(&h, "ap-absent", &absent).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an absent agent is a decision, not an error: {response}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["decision"],
        Value::Bool(false)
    );
}

#[tokio::test]
async fn an_agent_check_without_a_tool_is_refused_rather_than_answered() {
    // `resource.id` names the tool, and this is the one profile that reads it. Without one
    // there is no question: answering would mean deciding "may this agent call SOME tool",
    // which no PEP asked.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    let no_tool = json!({
        "subject": { "type": "agent", "id": f.agent },
        "resource": { "type": "tool" },
        "action": { "name": "call" },
        "context": { "organization_id": f.organization },
    });
    let (status, response) = f.refuse(&h, "ap-no-tool", &no_tool).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("resource_id_required"), "{response}");

    // And a resource type that is not `tool`: an agent subject asks one kind of question.
    let wrong_type = json!({
        "subject": { "type": "agent", "id": f.agent },
        "resource": { "type": "billing.invoice", "id": "inv_1" },
        "action": { "name": "read" },
        "context": { "organization_id": f.organization },
    });
    let (status, response) = f.refuse(&h, "ap-wrong-type", &wrong_type).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("resource_type_unsupported"), "{response}");
}

#[tokio::test]
async fn with_the_profile_off_an_agent_subject_is_refused_exactly_as_before() {
    // The DEFAULT. Not "the endpoint refuses an agent" but "the subject type has no meaning
    // here", which is the same refusal an unrecognised type has always drawn -- so a
    // deployment that has not acknowledged the draft cannot tell from the answer that the type
    // means something in this build.
    let h = Harness::start_with_agent_tool_profile(50, false).await;
    let f = Fixture::build(&h).await;

    let (status, response) = f
        .refuse(
            &h,
            "ap-off",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(
        response.contains("subject_type_unsupported"),
        "the refusal is the one an unrecognised type has always drawn: {response}"
    );

    // And it is byte-identical to what a genuinely unknown type draws, so the answer is not an
    // oracle for the profile's presence.
    let unknown = json!({
        "subject": { "type": "wombat", "id": f.agent },
        "resource": { "type": "tool", "id": DECLARED_AND_PERMITTED },
        "action": { "name": "call" },
        "context": { "organization_id": f.organization },
    });
    let (unknown_status, unknown_response) = f.refuse(&h, "ap-unknown", &unknown).await;
    assert_eq!(unknown_status, status);
    assert_eq!(unknown_response, response);
}

/// A well-formed scoped id that names nothing, from one that names something.
///
/// A scoped id carries a fixed-width base64 payload, so an id built by hand
/// (`agp_{env}_absent`) is refused by the PARSER rather than reaching the not-found branch.
/// Flipping the last payload character keeps the shape and changes the identity.
fn flip_last(id: &str) -> String {
    let mut chars: Vec<char> = id.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

#[tokio::test]
async fn an_agent_whose_human_can_no_longer_authenticate_is_denied() {
    // "An agent cannot outlive the revocation of the person it acts for" was true only of
    // DELETION and of membership removal: the effective-permission closure filters
    // `deleted_at IS NULL` and an active membership and reads `users.state` nowhere, so an
    // operator who BLOCKED someone left that person's agent fully authorized here.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    // The control: it allows while the person is active, so the denial below is the STATE.
    assert!(
        f.evaluate(
            &h,
            "ap-human-before",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await
    );

    // POST, not PUT: `setUserState` is registered `post` and takes a required idempotency
    // key. The sibling AGENT state route IS a `put`, which is what made the copy look right.
    let (status, _, body) = h
        .post(
            &format!("{}/users/{}/state", f.base(), f.user),
            "ap-block-human",
            &json!({ "state": "blocked" }).to_string(),
        )
        .await;
    assert!(status.is_success(), "block the human: {body}");

    assert!(
        !f.evaluate(
            &h,
            "ap-human-after",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await,
        "a blocked person's agent authorizes nothing, or the ceiling is not a ceiling"
    );
}

#[tokio::test]
async fn a_revoked_agent_is_denied_as_a_suspended_one_is() {
    // `revoked` is the other non-live state, and the doc claims both. Suspension alone was
    // tested, so `can_obtain_tokens` could have been written as `state != "suspended"` with
    // everything still green.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

    assert!(
        f.evaluate(
            &h,
            "ap-revoke-before",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await
    );

    let (status, _, body) = h
        .put(
            &format!(
                "{}/organizations/{}/agents/{}/state",
                f.base(),
                f.organization,
                f.agent
            ),
            &json!({ "state": "revoked" }).to_string(),
        )
        .await;
    assert!(status.is_success(), "revoke the agent: {body}");

    assert!(
        !f.evaluate(
            &h,
            "ap-revoke-after",
            &f.ask(&f.organization, DECLARED_AND_PERMITTED)
        )
        .await,
        "a revoked agent authorizes nothing"
    );
}
