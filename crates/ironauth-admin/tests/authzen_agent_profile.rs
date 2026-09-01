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
const DECLARED_AND_PERMITTED: &str = "deploy";
/// DECLARED by the agent, and its human holds no permission for it.
const DECLARED_NOT_PERMITTED: &str = "destroy";
/// PERMITTED to the human, and outside the agent's declared set.
const PERMITTED_NOT_DECLARED: &str = "rollback";

struct Fixture {
    tenant: String,
    environment: String,
    organization: String,
    agent: String,
    other_org: String,
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
            &json!({ "email": "operator@example.test" }),
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
        for tool in [DECLARED_AND_PERMITTED, PERMITTED_NOT_DECLARED] {
            let permission = created(
                h,
                &format!("{base}/permissions"),
                &format!("ap-perm-{tool}"),
                &json!({ "slug": format!("tool.{tool}"), "display_name": tool }),
            )
            .await;
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
            agent,
            other_org,
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
async fn a_suspended_agent_is_denied_while_its_human_is_unchanged() {
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
}

#[tokio::test]
async fn an_agent_of_another_organization_is_denied_rather_than_answered() {
    // The confinement every other read on this surface has. Without it a PEP in one
    // organization could ask about another's agent and get a decision computed from grants it
    // has no business seeing.
    let h = Harness::start_with_agent_tool_profile(50, true).await;
    let f = Fixture::build(&h).await;

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

    let absent = json!({
        "subject": { "type": "agent", "id": format!("agp_{}_absent", f.environment) },
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
