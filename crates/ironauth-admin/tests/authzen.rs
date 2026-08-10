// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `AuthZEN` 1.0 policy decision point (issue #100, criteria 1 to 3), over a real database.
//!
//! The resolution the `PDP` answers from is pinned exhaustively one layer down, in
//! `ironauth-store`'s `effective_permissions.rs` (the user arm) and `permission_parity.rs` (the
//! service-account arm). Repeating any of that here would be a second, weaker copy of it.
//!
//! What this file pins is everything the HTTP layer ADDS, which is where the mapping from an
//! `AuthZEN` request onto that resolution can go wrong:
//!
//! * The permission slug is `"{resource.type}.{action.name}"` as a PURE JOIN. A request that
//!   differs only in case gets `false`, because the grant path would never have written the
//!   normalised spelling and a `PDP` that normalises answers about a slug that does not exist.
//! * The organization comes from `context.organization_id`, and its ABSENCE is refused rather
//!   than defaulted. A guessed organization produces a decision indistinguishable from a
//!   correct allow, so there is no safe default to pick.
//! * `subject.type` selects the resolution arm and an unrecognised one is REFUSED. A `PDP` that
//!   fell back to the user arm would answer a question about somebody else.
//! * The batch endpoint inherits defaults, lets an entry override them, and resolves the
//!   organization PER ENTRY. Hoisting that resolution would silently answer every entry of a
//!   cross-organization batch against the first one's, which is the failure this asserts
//!   against directly by putting the same subject and slug in two organizations with different
//!   answers.
//! * `deny_on_first_deny` OMITS the entries it never performed. Reporting them `false` would be
//!   indistinguishable from a real deny, and a `PEP` would cache the wrong answer.
//! * The two endpoints answer IDENTICALLY for the same state. They share one `decide`, and this
//!   is the assertion that would catch them growing a second one.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, OrganizationId, Scope, TenantId, UserId};
use serde_json::{Value, json};

/// The permission this file grants and asks about. Deliberately carries a dot of its own, so a
/// join that split on dots rather than appending would be caught.
const GRANTED_TYPE: &str = "billing.invoice";
const GRANTED_ACTION: &str = "read";
const GRANTED_SLUG: &str = "billing.invoice.read";

/// A fixture: one tenant and environment, one user, and two organizations in which that user
/// holds DIFFERENT permissions. `granted` binds the user to a role carrying [`GRANTED_SLUG`];
/// `ungranted` gives the same user a membership and nothing else.
struct Fixture {
    tenant: String,
    environment: String,
    user: String,
    granted: String,
    ungranted: String,
}

impl Fixture {
    async fn build(h: &Harness) -> Self {
        let (tenant, environment) = h.create_tenant("acme", "authzen").await;
        let base = format!("/v1/tenants/{tenant}/environments/{environment}");

        let user = created(
            h,
            &format!("{base}/users"),
            "az-user",
            &json!({ "identifier": "pdp@example.test" }),
        )
        .await;
        let granted = created(
            h,
            &format!("{base}/organizations"),
            "az-org-granted",
            &json!({ "display_name": "Granted" }),
        )
        .await;
        let ungranted = created(
            h,
            &format!("{base}/organizations"),
            "az-org-ungranted",
            &json!({ "display_name": "Bare" }),
        )
        .await;

        let permission = created(
            h,
            &format!("{base}/permissions"),
            "az-perm",
            &json!({ "slug": GRANTED_SLUG, "display_name": "Read invoices" }),
        )
        .await;
        let role = created(
            h,
            &format!("{base}/organizations/{granted}/roles"),
            "az-role",
            &json!({ "slug": "accountant", "display_name": "Accountant" }),
        )
        .await;
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{granted}/roles/{role}/permissions"),
                "az-role-perm",
                &json!({ "permission_id": permission }).to_string(),
            )
            .await;
        assert!(
            status.is_success(),
            "attach the permission to the role: {status} {body}"
        );

        // The same user in both organizations, so a wrong-organization answer cannot hide
        // behind the subject simply not being a member there.
        for (org, key) in [
            (&granted, "az-mem-granted"),
            (&ungranted, "az-mem-ungranted"),
        ] {
            let membership = created(
                h,
                &format!("{base}/organizations/{org}/memberships"),
                key,
                &json!({ "user_id": user }),
            )
            .await;
            if org == &granted {
                let (status, _, body) = h
                    .post(
                        &format!("{base}/organizations/{org}/memberships/{membership}/roles"),
                        "az-mem-role",
                        &json!({ "role_id": role }).to_string(),
                    )
                    .await;
                assert!(
                    status.is_success(),
                    "assign the role to the membership: {status} {body}"
                );
            }
        }

        Self {
            tenant,
            environment,
            user,
            granted,
            ungranted,
        }
    }

    fn base(&self) -> String {
        let (tenant, environment) = (&self.tenant, &self.environment);
        format!("/v1/tenants/{tenant}/environments/{environment}")
    }

    /// One evaluation body for this fixture's user.
    fn ask(&self, org: &str, resource_type: &str, action: &str) -> Value {
        json!({
            "subject": { "type": "user", "id": self.user },
            "resource": { "type": resource_type },
            "action": { "name": action },
            "context": { "organization_id": org },
        })
    }

    /// The singular endpoint's decision, which must be a 200.
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

    /// The batch endpoint's decisions, which must be a 200.
    async fn evaluate_batch(&self, h: &Harness, key: &str, body: &Value) -> Vec<bool> {
        let (status, _, response) = h
            .post(
                &format!("{}/access/v1/evaluations", self.base()),
                key,
                &body.to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "evaluations: {response}");
        serde_json::from_str::<Value>(&response).expect("json")["evaluations"]
            .as_array()
            .expect("evaluations is an array")
            .iter()
            .map(|entry| entry["decision"].as_bool().expect("decision is a bool"))
            .collect()
    }

    /// The status and body of a singular evaluation that is expected to be refused.
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

/// POST `body` to `path` and return the created row's id.
async fn created(h: &Harness, path: &str, key: &str, body: &Value) -> String {
    let (status, _, response) = h.post(path, key, &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "create at {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("the created row carries an id")
        .to_owned()
}

/// The granted slug allows and an ungranted one denies, in the organization that holds the
/// grant. The floor everything else in this file stands on.
#[tokio::test]
async fn the_pdp_allows_a_granted_permission_and_denies_one_nobody_holds() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    assert!(
        f.evaluate(
            &h,
            "az-allow",
            &f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION)
        )
        .await,
        "the subject holds {GRANTED_SLUG} through a role in this organization"
    );
    assert!(
        !f.evaluate(&h, "az-deny", &f.ask(&f.granted, GRANTED_TYPE, "write"))
            .await,
        "nothing grants billing.invoice.write, and a PDP that allowed it would be allowing \
         every action name it was handed"
    );
}

/// The slug is a pure join: a request differing only in CASE is denied.
///
/// Normalising would answer for a slug the grant path never writes, and a permission granted
/// under one spelling and checked under another is the exact disagreement this endpoint exists
/// to be free of. The join is also asserted not to be a split: [`GRANTED_TYPE`] already carries
/// a dot, so an implementation that treated the type as a single segment would fail the test
/// above rather than this one.
#[tokio::test]
async fn the_slug_is_a_pure_join_and_a_differently_cased_request_is_denied() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    for (label, resource_type, action) in [
        ("an upper-cased type", "Billing.Invoice", GRANTED_ACTION),
        ("an upper-cased action", GRANTED_TYPE, "READ"),
        ("a padded type", " billing.invoice", GRANTED_ACTION),
        ("a padded action", GRANTED_TYPE, "read "),
    ] {
        assert!(
            !f.evaluate(
                &h,
                &format!("az-case-{resource_type}-{action}"),
                &f.ask(&f.granted, resource_type, action)
            )
            .await,
            "{label} produced a slug the grant path would never have written, and the PDP \
             answered for it anyway"
        );
    }
}

/// Permissions are organization scoped, so an evaluation carrying no organization has no
/// answer. It is refused rather than defaulted, in every shape of absence.
#[tokio::test]
async fn an_evaluation_without_an_organization_is_refused_rather_than_defaulted() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    for (label, context) in [
        ("no context at all", json!({})),
        ("a context naming other keys", json!({ "tenant": "acme" })),
        ("an empty organization", json!({ "organization_id": "" })),
        (
            "a whitespace organization",
            json!({ "organization_id": "   " }),
        ),
        (
            "a non-string organization",
            json!({ "organization_id": 42 }),
        ),
    ] {
        let mut body = f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION);
        body["context"] = context;
        let (status, response) = f.refuse(&h, &format!("az-noorg-{label}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was answered instead of refused: {response}"
        );
        assert!(
            response.contains("organization_required"),
            "{label} must be refused by NAME, so a PEP author is told which field is wrong: \
             {response}"
        );
    }
}

/// `subject.type` selects the resolution arm, an unrecognised one is refused, and an id of the
/// wrong kind is refused by the arm it was routed to.
///
/// The last part is what says the two arms are distinct. An implementation that collapsed them
/// into the user arm would still refuse the `service_account` request, but it would refuse it
/// with the user arm's message.
#[tokio::test]
async fn an_unsupported_subject_type_is_refused_rather_than_treated_as_a_user() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    for kind in ["group", "USER", "user_account", ""] {
        let mut body = f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION);
        body["subject"]["type"] = json!(kind);
        let (status, response) = f.refuse(&h, &format!("az-kind-{kind}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "subject.type `{kind}` was answered rather than refused, which answers a question \
             about somebody else: {response}"
        );
        assert!(
            response.contains("subject_type_unsupported"),
            "the refusal must name the rule: {response}"
        );
    }

    // The user's own id, declared as a service account, reaches the SERVICE-ACCOUNT arm.
    let mut body = f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION);
    body["subject"]["type"] = json!("service_account");
    let (status, response) = f.refuse(&h, "az-wrong-arm", &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a usr_ id was accepted as a service account: {response}"
    );
    assert!(
        response.contains("not a service account"),
        "the refusal must come from the service-account arm, or the two arms have collapsed \
         into one: {response}"
    );
}

/// The batch inherits shared defaults, lets an entry override them, and resolves the
/// organization PER ENTRY.
///
/// The two entries differ ONLY in the organization and carry the same subject and slug, so a
/// hoisted resolution would answer both against the first one's and return two `true`.
#[tokio::test]
async fn the_batch_inherits_defaults_and_resolves_the_organization_per_entry() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    let decisions = f
        .evaluate_batch(
            &h,
            "az-batch-orgs",
            &json!({
                "subject": { "type": "user", "id": f.user },
                "resource": { "type": GRANTED_TYPE },
                "action": { "name": GRANTED_ACTION },
                "evaluations": [
                    { "context": { "organization_id": f.granted } },
                    { "context": { "organization_id": f.ungranted } },
                ],
            }),
        )
        .await;
    assert_eq!(
        decisions,
        vec![true, false],
        "the same subject and slug must resolve per organization; two `true` means every \
         entry was answered against the first entry's organization"
    );

    // An entry may override the shared subject, resource and action too.
    let decisions = f
        .evaluate_batch(
            &h,
            "az-batch-overrides",
            &json!({
                "subject": { "type": "user", "id": f.user },
                "resource": { "type": GRANTED_TYPE },
                "action": { "name": GRANTED_ACTION },
                "context": { "organization_id": f.granted },
                "evaluations": [
                    {},
                    { "action": { "name": "write" } },
                    { "resource": { "type": "billing.credit" } },
                ],
            }),
        )
        .await;
    assert_eq!(
        decisions,
        vec![true, false, false],
        "an entry that names a field must override the shared default rather than be ignored"
    );
}

/// An entry with no value for a required field, and no shared default to inherit, is refused by
/// name rather than answered `false`.
#[tokio::test]
async fn a_batch_entry_missing_a_required_field_after_defaults_is_refused() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;
    let path = format!("{}/access/v1/evaluations", f.base());

    for (label, expected, body) in [
        (
            "no subject anywhere",
            "subject_required",
            json!({
                "resource": { "type": GRANTED_TYPE },
                "action": { "name": GRANTED_ACTION },
                "context": { "organization_id": f.granted },
                "evaluations": [{}],
            }),
        ),
        (
            "no resource anywhere",
            "resource_required",
            json!({
                "subject": { "type": "user", "id": f.user },
                "action": { "name": GRANTED_ACTION },
                "context": { "organization_id": f.granted },
                "evaluations": [{}],
            }),
        ),
        (
            "no action anywhere",
            "action_required",
            json!({
                "subject": { "type": "user", "id": f.user },
                "resource": { "type": GRANTED_TYPE },
                "context": { "organization_id": f.granted },
                "evaluations": [{}],
            }),
        ),
    ] {
        let (status, _, response) = h
            .post(&path, &format!("az-missing-{expected}"), &body.to_string())
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was answered rather than refused: {response}"
        );
        assert!(
            response.contains(expected),
            "{label} must be refused as `{expected}`: {response}"
        );
    }
}

/// `deny_on_first_deny` OMITS the entries it never performed.
///
/// This is the sharp one. Reporting the skipped entries as `false` would be indistinguishable
/// from a real deny, and a `PEP` would cache a decision nothing made. The same batch is run
/// twice, with and without the option, so the assertion is about the OPTION and not about the
/// fixture: the third entry is `true` when it is reached.
#[tokio::test]
async fn deny_on_first_deny_omits_the_remaining_entries_rather_than_reporting_them_false() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    let entries = json!([
        { "context": { "organization_id": f.granted } },
        { "context": { "organization_id": f.ungranted } },
        { "context": { "organization_id": f.granted } },
    ]);
    let request = |stop: bool| {
        json!({
            "subject": { "type": "user", "id": f.user },
            "resource": { "type": GRANTED_TYPE },
            "action": { "name": GRANTED_ACTION },
            "evaluations": entries,
            "options": { "deny_on_first_deny": stop },
        })
    };

    let full = f.evaluate_batch(&h, "az-nostop", &request(false)).await;
    assert_eq!(
        full,
        vec![true, false, true],
        "without the option every entry is performed, and the third one ALLOWS"
    );

    let stopped = f.evaluate_batch(&h, "az-stop", &request(true)).await;
    assert_eq!(
        stopped,
        vec![true, false],
        "the third entry must be ABSENT, not `false`: a caller cannot tell a reported `false` \
         from a real deny and would cache a decision nothing made"
    );
}

/// The two endpoints answer identically for the same state.
///
/// They share one `decide`, and the criterion is that a claim check and a `PDP` check never
/// disagree. A second copy of the resolution behind either endpoint is what this catches.
#[tokio::test]
async fn both_endpoints_answer_identically_for_the_same_state() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    for (index, (org, resource_type, action)) in [
        (&f.granted, GRANTED_TYPE, GRANTED_ACTION),
        (&f.granted, GRANTED_TYPE, "write"),
        (&f.ungranted, GRANTED_TYPE, GRANTED_ACTION),
        (&f.ungranted, "billing.credit", "approve"),
    ]
    .into_iter()
    .enumerate()
    {
        let single = f
            .evaluate(
                &h,
                &format!("az-agree-one-{index}"),
                &f.ask(org, resource_type, action),
            )
            .await;
        let batch = f
            .evaluate_batch(
                &h,
                &format!("az-agree-many-{index}"),
                &json!({ "evaluations": [f.ask(org, resource_type, action)] }),
            )
            .await;
        assert_eq!(
            batch,
            vec![single],
            "the singular and batch endpoints disagreed about {resource_type}.{action}, which \
             means one of them has grown its own copy of the resolution"
        );
    }
}

/// An organization that is not a live row of THIS scope is not answered for.
///
/// A `PDP` that answered `false` for a foreign organization would be reporting a deny where the
/// truth is that the caller asked about something outside the scope it authenticated to.
#[tokio::test]
async fn an_organization_outside_the_scope_is_refused_rather_than_denied() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    let (other_tenant, other_environment) = h.create_tenant("globex", "authzen-other").await;
    let foreign = created(
        &h,
        &format!("/v1/tenants/{other_tenant}/environments/{other_environment}/organizations"),
        "az-foreign-org",
        &json!({ "display_name": "Foreign" }),
    )
    .await;

    let (status, response) = f
        .refuse(
            &h,
            "az-foreign",
            &f.ask(&foreign, GRANTED_TYPE, GRANTED_ACTION),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an organization of another scope must not be decided for: {response}"
    );

    // A syntactically impossible organization is likewise refused rather than denied.
    let (status, response) = f
        .refuse(
            &h,
            "az-nonsense-org",
            &f.ask("not-an-organization", GRANTED_TYPE, GRANTED_ACTION),
        )
        .await;
    assert!(
        status.is_client_error() && status != StatusCode::OK,
        "an unparseable organization must be refused: {status} {response}"
    );
}

/// A soft-deleted environment stops DECIDING, and stops for a malformed request too, while its
/// discovery document stays served.
///
/// The asymmetry is the point and is the reason this test exists beside `live_surface.rs`'s
/// whole-surface sweep. That sweep filters to WRITES, so it drives the two evaluation endpoints
/// and is silent about the discovery GET. Every other read on this surface stays served for a
/// decommissioned environment, and discovery is one of those: it returns endpoint paths, not a
/// decision. An evaluation returns a decision a `PEP` acts on, so an environment that kept
/// answering would keep admitting traffic after an operator deleted it.
///
/// The malformed-body half is not incidental. If the fence ran after the body were parsed, a
/// deleted environment would refuse only the requests that were already well formed and would
/// still be telling a prober which shape of request it recognises.
#[tokio::test]
async fn a_soft_deleted_environment_stops_deciding_but_still_describes_itself() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;
    let well_formed = f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION).to_string();

    // While it is live, both endpoints decide.
    assert!(
        f.evaluate(
            &h,
            "az-live-before",
            &f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION)
        )
        .await,
        "the fixture must be deciding before the environment is deleted, or the refusals \
         below would prove nothing"
    );

    let (tenant, environment) = (&f.tenant, &f.environment);
    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert!(
        status.is_success(),
        "soft-delete the environment: {status} {body}"
    );

    for (label, path, payload) in [
        (
            "a well formed evaluation",
            format!("{}/access/v1/evaluation", f.base()),
            well_formed.clone(),
        ),
        (
            "a malformed evaluation",
            format!("{}/access/v1/evaluation", f.base()),
            "{".to_owned(),
        ),
        (
            "a well formed batch",
            format!("{}/access/v1/evaluations", f.base()),
            serde_json::json!({
                "subject": { "type": "user", "id": f.user },
                "resource": { "type": GRANTED_TYPE },
                "action": { "name": GRANTED_ACTION },
                "context": { "organization_id": f.granted },
                "evaluations": [{}],
            })
            .to_string(),
        ),
        (
            "a malformed batch",
            format!("{}/access/v1/evaluations", f.base()),
            "{".to_owned(),
        ),
    ] {
        let (status, _, response) = h
            .post(&path, &format!("az-deleted-{label}"), &payload)
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label} was answered by a soft-deleted environment, which keeps admitting \
             traffic an operator believes they revoked: {response}"
        );
    }

    let (status, _, body) = h
        .get(&format!("{}/.well-known/authzen-configuration", f.base()))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "discovery returns no decision and must stay served for a decommissioned \
         environment, like every other read on this surface: {body}"
    );
}

/// A soft-deleted ORGANIZATION is refused rather than answered `false`.
///
/// This is what `resolve_live_org` contributes once the ENVIRONMENT fence has moved upstream:
/// a `false` here would report a deny where the truth is that the organization the caller asked
/// about is gone, and a `PEP` cannot tell those apart. It is also the assertion that keeps the
/// call from decaying into a ungranted id parse.
#[tokio::test]
async fn a_soft_deleted_organization_is_refused_rather_than_denied() {
    let h = Harness::start(50).await;
    let f = Fixture::build(&h).await;

    assert!(
        f.evaluate(
            &h,
            "az-org-live",
            &f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION)
        )
        .await,
        "the organization must be deciding before it is deleted"
    );

    let (status, _, body) = h
        .delete(&format!("{}/organizations/{}", f.base(), f.granted))
        .await;
    assert!(
        status.is_success(),
        "soft-delete the organization: {status} {body}"
    );

    let (status, response) = f
        .refuse(
            &h,
            "az-org-deleted",
            &f.ask(&f.granted, GRANTED_TYPE, GRANTED_ACTION),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted organization must be refused, not denied: a PEP cannot tell a reported \
         `false` from a grant that was taken away: {response}"
    );
}

/// Issue #100 criterion 3: over DIRECT, MULTI-ROLE and GROUP-INHERITED grants, every decision
/// this endpoint returns equals what the token-claim path would resolve for the same state.
///
/// The comparison is against [`OrgGroupRepo::effective_permissions`] read directly, which is
/// not an approximation of the claim path but the very function it calls
/// (`ironauth-oidc`'s `token.rs::resolve_effective_permissions`). Asserting against a
/// hand-written expected set instead would pin what this test's author believed, and the
/// criterion is about AGREEMENT: a claim check and a PDP check must never disagree.
///
/// The probe set is deliberately the whole vocabulary rather than the granted slugs. A PDP that
/// allowed everything would satisfy any all-allow expectation, so the denials carry as much of
/// the assertion as the allows.
// The fixture is long because the criterion names three grant SHAPES and all three have to be
// built. Splitting it would put the state in one function and the agreement in another, and the
// agreement is only meaningful over the state this one builds.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_decision_agrees_with_the_resolution_the_token_claims_are_built_from() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "authzen-agree").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    let user = created(
        &h,
        &format!("{base}/users"),
        "ag-user",
        &json!({ "identifier": "agree@example.test" }),
    )
    .await;
    let org = created(
        &h,
        &format!("{base}/organizations"),
        "ag-org",
        &json!({ "display_name": "Agree" }),
    )
    .await;
    let membership = created(
        &h,
        &format!("{base}/organizations/{org}/memberships"),
        "ag-mem",
        &json!({ "user_id": user }),
    )
    .await;

    // The vocabulary. `unheld` is attached to a role nobody holds, so it probes the case a
    // PDP most easily gets wrong: a permission that EXISTS in this organization and is still
    // not the subject's.
    let slugs = [
        "billing.invoice.read",
        "billing.invoice.write",
        "audit.log.read",
        "secrets.key.rotate",
        "nothing.at.all",
    ];
    let mut permissions = std::collections::BTreeMap::new();
    for slug in slugs {
        let id = created(
            &h,
            &format!("{base}/permissions"),
            &format!("ag-perm-{slug}"),
            &json!({ "slug": slug, "display_name": slug }),
        )
        .await;
        permissions.insert(slug, id);
    }

    // Three roles carrying one permission each, reaching the subject three DIFFERENT ways.
    let mut roles = std::collections::BTreeMap::new();
    for (role_slug, permission_slug) in [
        ("direct", "billing.invoice.read"),
        ("second", "billing.invoice.write"),
        ("inherited", "audit.log.read"),
        ("unheld", "secrets.key.rotate"),
    ] {
        let role = created(
            &h,
            &format!("{base}/organizations/{org}/roles"),
            &format!("ag-role-{role_slug}"),
            &json!({ "slug": role_slug, "display_name": role_slug }),
        )
        .await;
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{org}/roles/{role}/permissions"),
                &format!("ag-rp-{role_slug}"),
                &json!({ "permission_id": permissions[permission_slug] }).to_string(),
            )
            .await;
        assert!(status.is_success(), "attach {permission_slug}: {body}");
        roles.insert(role_slug, role);
    }

    // DIRECT and MULTI-ROLE: two roles on the membership itself.
    for role_slug in ["direct", "second"] {
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{org}/memberships/{membership}/roles"),
                &format!("ag-mr-{role_slug}"),
                &json!({ "role_id": roles[role_slug] }).to_string(),
            )
            .await;
        assert!(status.is_success(), "assign {role_slug}: {body}");
    }

    // GROUP-INHERITED: a child group holds the member, the PARENT holds the role.
    let parent = created(
        &h,
        &format!("{base}/organizations/{org}/groups"),
        "ag-group-parent",
        &json!({ "slug": "engineering", "display_name": "Engineering" }),
    )
    .await;
    let child = created(
        &h,
        &format!("{base}/organizations/{org}/groups"),
        "ag-group-child",
        &json!({ "slug": "platform", "display_name": "Platform", "parent_id": parent }),
    )
    .await;
    let (status, _, body) = h
        .post(
            &format!("{base}/organizations/{org}/groups/{child}/members"),
            "ag-gm",
            &json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert!(status.is_success(), "add the group member: {body}");
    let (status, _, body) = h
        .post(
            &format!("{base}/organizations/{org}/groups/{parent}/roles"),
            "ag-gr",
            &json!({ "role_id": roles["inherited"] }).to_string(),
        )
        .await;
    assert!(status.is_success(), "assign the group role: {body}");

    // The resolution the claims are built from, read directly.
    let resolved = h
        .store()
        .management()
        .org_groups(scope)
        .effective_permissions(
            &OrganizationId::parse_in_scope(&org, &scope).expect("organization id"),
            &UserId::parse_in_scope(&user, &scope).expect("user id"),
            8,
        )
        .await
        .expect("resolve the effective permissions");
    // The fixture must actually exercise all three shapes, or the agreement below is an
    // agreement about an empty set.
    for expected in [
        "billing.invoice.read",
        "billing.invoice.write",
        "audit.log.read",
    ] {
        assert!(
            resolved.contains(expected),
            "the fixture failed to grant {expected}, so this test would be comparing two \
             functions over a state that exercises nothing: {resolved:?}"
        );
    }
    assert!(
        !resolved.contains("secrets.key.rotate"),
        "the unheld role's permission must NOT resolve, or the denials below prove nothing"
    );

    // Every slug, whether granted or not, decided both ways and compared.
    for slug in slugs {
        let (resource_type, action) = slug.rsplit_once('.').expect("the slug has an action");
        let body = json!({
            "subject": { "type": "user", "id": user },
            "resource": { "type": resource_type },
            "action": { "name": action },
            "context": { "organization_id": org },
        });
        let (status, _, response) = h
            .post(
                &format!("{base}/access/v1/evaluation"),
                &format!("ag-eval-{slug}"),
                &body.to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "evaluate {slug}: {response}");
        let decision = serde_json::from_str::<Value>(&response).expect("json")["decision"]
            .as_bool()
            .expect("decision is a bool");
        assert_eq!(
            decision,
            resolved.contains(slug),
            "the PDP and the claim resolution disagree about {slug}, which is exactly the \
             disagreement this endpoint exists to be free of: resolved {resolved:?}"
        );
    }
}
