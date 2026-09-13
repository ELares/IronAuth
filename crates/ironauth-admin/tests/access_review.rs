// SPDX-License-Identifier: MIT OR Apache-2.0

//! The access-review export surface (issue #145 criterion 1).
//!
//! The rows are covered in `ironauth-store`. What is worth driving here is what the HTTP layer
//! adds and could get wrong: that both formats are served with the content type a consumer
//! keys on, that an unknown format is refused rather than silently defaulted, and that the
//! export is bounded by the organization in the path.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str, name: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": name }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Bind a fresh user into `org` and return `(user id, membership id)`.
///
/// BOTH, because the export reports the subject and keys the row on the membership. A caller
/// that knows only one of them cannot name every id in a row, and the comparison below needs
/// to name every id it sees or it is comparing run-specific strings.
async fn add_member(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    handle: &str,
) -> (String, String) {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let (status, _, body) = h
        .post(
            &users,
            &format!("ak-user-{handle}"),
            &serde_json::json!({ "identifier": handle }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {body}");
    let user = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let memberships =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");
    let (status, _, body) = h
        .post(
            &memberships,
            &format!("ak-mem-{handle}"),
            &serde_json::json!({ "user_id": user }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create membership: {body}");
    let membership = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    (user, membership)
}

#[tokio::test]
async fn both_formats_describe_the_same_review() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org", "Acme").await;
    let (_user, membership) = add_member(&h, &tenant, &environment, &org, "alice@acme.test").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/access-review"
    );

    let (status, headers, jsonl) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "the default export: {jsonl}");
    let (status, csv_headers, csv) = h.get(&format!("{base}?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "the CSV export: {csv}");

    // THE MEMBER IS IN BOTH. A pair of empty files would satisfy any comparison between them,
    // which is the shape this assertion exists to reject.
    assert!(
        jsonl.contains(&membership),
        "the member is missing from the JSONL export: {jsonl}"
    );
    assert!(
        csv.contains(&membership),
        "the member is missing from the CSV export: {csv}"
    );
    // THE CONTENT TYPES, which this file names as its first purpose and used to assert
    // nowhere. A consumer keys on them: a spreadsheet handed application/x-ndjson opens a
    // blob, and a streaming reader handed text/csv parses a header row as data.
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-ndjson"),
        "the default export must be newline-delimited JSON"
    );
    assert_eq!(
        csv_headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/csv; charset=utf-8"),
        "the CSV export must say so, with its charset"
    );

    // AND THE CSV CARRIES ITS HEADER, which is what a consumer looks fields up by.
    assert!(
        csv.starts_with("organization_id,principal_kind,membership_id,subject_id,role_slug"),
        "the CSV export has no header: {csv}"
    );
}

#[tokio::test]
async fn an_unknown_format_is_refused_rather_than_defaulted() {
    // A caller asking for `xlsx` and receiving JSON Lines under a 200 has an evidence
    // pipeline that silently reads the wrong thing.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org", "Acme").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/access-review"
    );

    let (status, _, body) = h.get(&format!("{base}?format=xlsx")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown format must be refused: {body}"
    );
    // THE CONTROL: the endpoint answers for a format it does serve, so the refusal above is
    // the validation and not a broken route.
    let (status, _, body) = h.get(&format!("{base}?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "csv must still be served: {body}");
}

#[tokio::test]
async fn the_export_is_bounded_by_the_organization_in_the_path() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "ak-mine", "Contoso").await;
    let theirs = create_org(&h, &tenant, &environment, "ak-theirs", "Initech").await;
    let (_, my_member) = add_member(&h, &tenant, &environment, &mine, "alice@contoso.test").await;
    let (_, their_member) =
        add_member(&h, &tenant, &environment, &theirs, "bob@initech.test").await;

    let (status, _, body) = h
        .get(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{mine}/access-review"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // THE CONTROL FIRST: an empty export satisfies the absence below.
    assert!(
        body.contains(&my_member),
        "our own member is missing, so the absence below proves nothing: {body}"
    );
    assert!(
        !body.contains(&their_member),
        "one organization's access review carried another's member: {body}"
    );
}

/// Create a role and return its id.
async fn create_role(h: &Harness, org_base: &str, slug: &str, key: &str) -> String {
    let (status, _, body) = h
        .post(
            &format!("{org_base}/roles"),
            key,
            &serde_json::json!({ "slug": slug, "display_name": slug }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create role {slug}: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Create a group, optionally under `parent`, and return its id.
async fn create_group(
    h: &Harness,
    org_base: &str,
    slug: &str,
    parent: Option<&str>,
    key: &str,
) -> String {
    let mut request = serde_json::json!({ "slug": slug, "display_name": slug });
    if let Some(parent) = parent {
        request["parent_id"] = Value::String(parent.to_owned());
    }
    let (status, _, body) = h
        .post(&format!("{org_base}/groups"), key, &request.to_string())
        .await;
    assert_eq!(status, StatusCode::CREATED, "create group {slug}: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// A compliance consumer ingests a REAL export and reconstructs who has which role
/// (issue #145 criterion 1).
///
/// # What this measures that the store's round trip does not
///
/// `ironauth-store` writes rows and reads them back with an independent parser, and
/// `access_review_fixture` pins the wire format against committed files. Both work on rows
/// handed to them. Neither one asks the question the criterion does: does the export SERVED
/// BY THIS ENDPOINT, over a real organization with a real group tree, tell a consumer who has
/// which role INCLUDING the derived assignments?
///
/// So the fixture here is built through the management API and consumed through
/// `ironauth_store::access_review::parse_*` -- the outside tool's half, sharing nothing with
/// the writer but the bytes. The assertion is the reconstruction, not the row count: a test
/// asserting "seven rows parsed" passes against an export that names the wrong people.
///
/// # The derived assignment is the point
///
/// `bob` is a member of `finance-ap`, and the role is assigned to its PARENT `finance`. He
/// holds it through the ancestor closure, through no assignment row that names him, and an
/// access review that reported only direct assignments would show him holding nothing while
/// his token carries `reports-reader`. That is the row a `SailPoint`- or `Vanta`-class consumer
/// is there to find, and the one an export is most likely to miss.
#[tokio::test]
async fn a_compliance_consumer_reconstructs_who_has_which_role_from_a_real_export() {
    // BOTH RESOLUTION TAILS, and finding out that this mattered took a surviving mutant.
    //
    // `Harness::start` ARMS the exploratory access-request feature, so an admin test built on
    // it resolves the USER half of the export through `EFFECTIVE_ROLE_GRANTS_TIME_BOXED_TAIL`.
    // Deleting the group arm from the PLAIN tail left this test green, because this test never
    // ran the plain tail. Whatever else that is, it is not coverage of the export as a
    // deployment without the flag serves it -- which is every deployment.
    //
    // THE USER HALF ONLY, and the distinction is the code's rather than a quibble.
    // `access_review_in_pages` drains members in two loops: the user loop branches on the
    // instant, and the SERVICE-ACCOUNT loop calls `effective_role_grants_for_service_account`,
    // which is hard-wired to the plain tail and has no time-boxed sibling. So a machine member
    // resolves through the plain tail whatever the flag says -- which is correct, because only
    // a USER can be the subject of an access request (`require_grantable` parses `subject_id`
    // as a `UserId`), so there is no time-boxed row for a machine member to miss. This
    // scenario seeds no machine member, so neither run below enters that loop; the
    // `service_account` row is covered end to end by the pinned store fixture instead, and the
    // route is driven with a real machine member in `live_surface`.
    //
    // WHAT THE SECOND RUN BUYS, stated exactly, because the first version of this comment
    // credited it with a measurement it does not make.
    //
    // The measurement is that the scenario's assertions -- which compare against ABSOLUTE
    // literals, not against the other run -- execute a second time with the plain tail
    // resolving the export. That is the coverage the surviving mutant showed was missing, and
    // it is strictly stronger than the two runs agreeing with each other.
    //
    // The equality below is a REDUNDANCY CHECK over the columns those assertions ignore
    // (`organization_id`, `principal_kind`, `subject_id`, `via_request_id`,
    // `granted_until_unix_ms`), and against this fixture it cannot currently fail. Measured,
    // not assumed: projecting a non-NULL `granted_until_micros` from all three copied arms of
    // the time-boxed tail leaves every test here green, because `decode_grants` discards those
    // two columns for any source that is not `time_boxed`. With no time-boxed grant in the
    // fixture, every column of every row is fixed outside the tail except the slug, the source
    // and the group -- which is precisely what the assertions already pin.
    //
    // It is kept rather than deleted because it becomes load-bearing the moment this fixture
    // grows a time-boxed grant, and because a wrong answer it WOULD catch is cheap to check.
    // It is not the thing that makes this test cover both tails.
    let armed = review_scenario(Harness::start(50).await).await;
    let plain = review_scenario(Harness::start_with_access_requests(50, false).await).await;
    assert_eq!(
        plain, armed,
        "the export answers differently with the exploratory feature off. With no live \
         time-boxed grant anywhere in the fixture the two tails have to agree, and a \
         difference here is the widened tail changing an answer it was merged promising not \
         to touch"
    );
}

/// Everything the review is OF: three roles, a default, a two-level group tree, three members,
/// one direct assignment and one group membership.
///
/// Returns `(finance group id, alice, bob, carol)` -- the membership ids, because the export
/// keys rows on the membership rather than on the user.
async fn seed_review_fixture(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
) -> Fixture {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org_base = format!("{base}/organizations/{org}");

    let billing = create_role(h, &org_base, "billing-admin", "ak-role-billing").await;
    let reports = create_role(h, &org_base, "reports-reader", "ak-role-reports").await;
    let baseline = create_role(h, &org_base, "member", "ak-role-member").await;

    // EVERY MEMBER holds this one, through no assignment row at all.
    let (status, _, body) = h
        .put(
            &format!("{org_base}/default-role"),
            &serde_json::json!({ "role_id": baseline }).to_string(),
        )
        .await;
    assert!(status.is_success(), "set the default role: {status} {body}");

    // A TWO-LEVEL TREE: the role is granted to the parent and the member sits in the child.
    let finance = create_group(h, &org_base, "finance", None, "ak-grp-finance").await;
    let finance_ap = create_group(
        h,
        &org_base,
        "finance-ap",
        Some(&finance),
        "ak-grp-finance-ap",
    )
    .await;
    let (status, _, body) = h
        .post(
            &format!("{org_base}/groups/{finance}/roles"),
            "ak-grp-role",
            &serde_json::json!({ "role_id": reports }).to_string(),
        )
        .await;
    assert!(status.is_success(), "grant the role to the group: {body}");

    let (alice_user, alice) = add_member(h, tenant, environment, org, "alice@acme.test").await;
    let (bob_user, bob) = add_member(h, tenant, environment, org, "bob@acme.test").await;
    // carol joins and is assigned nothing: the DEFAULT is all she holds.
    let (carol_user, carol) = add_member(h, tenant, environment, org, "carol@acme.test").await;

    let (status, _, body) = h
        .post(
            &format!("{org_base}/memberships/{alice}/roles"),
            "ak-direct",
            &serde_json::json!({ "role_id": billing }).to_string(),
        )
        .await;
    assert!(status.is_success(), "assign the direct role: {body}");
    let (status, _, body) = h
        .post(
            &format!("{org_base}/groups/{finance_ap}/members"),
            "ak-grp-member",
            &serde_json::json!({ "membership_id": bob }).to_string(),
        )
        .await;
    assert!(status.is_success(), "put bob in the child group: {body}");

    Fixture {
        finance,
        finance_ap,
        alice,
        bob,
        carol,
        alice_user,
        bob_user,
        carol_user,
    }
}

/// Every id the scenario minted, so a row can be named rather than compared as a string.
struct Fixture {
    finance: String,
    finance_ap: String,
    alice: String,
    bob: String,
    carol: String,
    alice_user: String,
    bob_user: String,
    carol_user: String,
}

/// Build the organization, export it, and return the reconstruction a consumer arrives at.
///
/// Returns EVERY parsed row with the run-specific ids replaced by stable names, sorted, so the
/// caller can compare two runs that minted different ids. The per-member assertions inside run
/// against the real ids; what is returned is deliberately WIDER than those assertions, because
/// a comparison between two values that are each already pinned to the same literal cannot
/// fail.
async fn review_scenario(h: Harness) -> Vec<Vec<(String, String)>> {
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org", "Acme").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org_base = format!("{base}/organizations/{org}");

    let f = seed_review_fixture(&h, &tenant, &environment, &org).await;
    let (finance, alice, bob, carol) = (
        f.finance.clone(),
        f.alice.clone(),
        f.bob.clone(),
        f.carol.clone(),
    );

    // THE INGEST. Both formats, parsed by the consumer's half of the contract.
    let export = format!("{org_base}/access-review");
    let (status, _, jsonl) = h.get(&export).await;
    assert_eq!(status, StatusCode::OK, "the JSONL export: {jsonl}");
    let (status, _, csv) = h.get(&format!("{export}?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "the CSV export: {csv}");

    let from_jsonl =
        ironauth_store::access_review::parse_jsonl(&jsonl).expect("a consumer parses the JSONL");
    let from_csv =
        ironauth_store::access_review::parse_csv(&csv).expect("a consumer parses the CSV");
    assert_eq!(
        from_jsonl, from_csv,
        "the two exports of one review do not describe the same thing"
    );

    // The reconstruction, keyed on the MEMBERSHIP so the assertion does not depend on the
    // order the resolver returned paths in.
    let describe = |membership: &str| {
        let mut paths: Vec<String> = from_csv
            .iter()
            .filter(|row| row.fields.get("membership_id").map(String::as_str) == Some(membership))
            .map(|row| {
                let get = |key: &str| row.fields.get(key).cloned().unwrap_or_default();
                match get("source").as_str() {
                    // BY SLUG, not by the id: two runs mint different ids, and a comparison
                    // between them would be a comparison between two random strings.
                    "group" if get("via_group_id") == finance => {
                        format!("{} by group via finance", get("role_slug"))
                    }
                    "group" => format!(
                        "{} by group via UNEXPECTED {}",
                        get("role_slug"),
                        get("via_group_id")
                    ),
                    "none" => "nothing".to_owned(),
                    other => format!("{} by {other}", get("role_slug")),
                }
            })
            .collect();
        paths.sort();
        paths
    };

    assert_eq!(
        describe(&alice),
        vec![
            "billing-admin by direct".to_owned(),
            "member by default".to_owned(),
        ],
        "alice holds a direct grant and the organization default"
    );
    assert_eq!(
        describe(&bob),
        vec![
            "member by default".to_owned(),
            "reports-reader by group via finance".to_owned(),
        ],
        "bob holds the role through the group his own group DESCENDS from. An export that \
         reported only assignment rows would show him holding nothing of the sort, while his \
         token carries it"
    );
    assert_eq!(
        describe(&carol),
        vec!["member by default".to_owned()],
        "carol was assigned nothing, so the default is all she holds"
    );

    // AND THE CONSUMER SEES EVERY MEMBER. A reconstruction over the people it happens to
    // mention would agree with itself while leaving somebody out of the evidence entirely.
    let mut members: Vec<String> = from_csv
        .iter()
        .filter_map(|row| row.fields.get("membership_id").cloned())
        .collect();
    members.sort();
    members.dedup();
    let mut expected = vec![alice.clone(), bob.clone(), carol.clone()];
    expected.sort();
    assert_eq!(
        members, expected,
        "the export has to carry a row for every member of the organization"
    );

    // WHAT THE TWO TAILS ARE COMPARED ON: every row, every column, with the run-specific ids
    // replaced by stable names. See the caller for what that comparison does and does not buy.
    normalise_rows(
        &from_csv,
        &[
            (&org, "ORG"),
            (&alice, "ALICE_MEMBERSHIP"),
            (&bob, "BOB_MEMBERSHIP"),
            (&carol, "CAROL_MEMBERSHIP"),
            (&f.alice_user, "ALICE_USER"),
            (&f.bob_user, "BOB_USER"),
            (&f.carol_user, "CAROL_USER"),
            (&f.finance, "FINANCE_GROUP"),
            (&f.finance_ap, "FINANCE_AP_GROUP"),
        ],
    )
}

/// Replace every id this scenario minted with a stable name, so two runs can be compared.
///
/// The first version of the two-run comparison returned the three `describe` vectors -- the
/// very expressions the scenario had already asserted equal to literals -- so the caller
/// compared two values pinned to the same constants and could not fail. This returns the whole
/// parsed table instead, which is at least WIDER than what those assertions fix.
fn normalise_rows(
    rows: &[ironauth_store::access_review::ConsumedRow],
    names: &[(&str, &str)],
) -> Vec<Vec<(String, String)>> {
    let mut normalised: Vec<Vec<(String, String)>> = rows
        .iter()
        .map(|row| {
            row.fields
                .iter()
                .map(|(column, value)| {
                    let stable = names
                        .iter()
                        .find(|(id, _)| id == value)
                        .map_or_else(|| value.clone(), |(_, name)| (*name).to_owned());
                    // AN ID THIS TEST DID NOT MINT is not normalisable, and leaving it in
                    // would make the two runs differ for a reason that is not a defect --
                    // which is how a comparison like this turns into a flake and then gets
                    // deleted. It is also a finding in its own right: the export is bounded by
                    // one organization, so every id in it should be one of ours.
                    assert!(
                        !["org_", "omb_", "usr_", "sva_", "grp_", "orl_", "agr_"]
                            .iter()
                            .any(|prefix| stable.starts_with(prefix)),
                        "the export carried an id this scenario never created, in column \
                         {column}: {value}"
                    );
                    (column.clone(), stable)
                })
                .collect()
        })
        .collect();
    normalised.sort();
    normalised
}
