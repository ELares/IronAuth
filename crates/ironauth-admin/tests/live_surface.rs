// SPDX-License-Identifier: MIT OR Apache-2.0

//! The LIVE-ENVIRONMENT contract for the whole management surface (issue #441).
//!
//! # The defect this file exists to catch
//!
//! The management router connects as `ironauth_control`, a deliberately least-privileged
//! role that holds only the grants a migration named for it. A handler that reaches a
//! relation nobody granted that role is refused by Postgres before any application logic
//! runs, and the refusal surfaces as an opaque 500 on a healthy deployment. Nothing about
//! the code reads wrong: the SQL is correct, the scoping is correct, the row is there. The
//! surface is simply dead.
//!
//! `abuse_bans` was the reported instance, and the reason it survived to a release is that
//! the whole abuse-ban surface had no integration test. This file makes that class of
//! omission structurally impossible for the surface as a whole.
//!
//! # Why a sweep, and why it is the WHOLE contract rather than the environment prefix
//!
//! [`absent_environment`] sweeps the same router for a different property, and its live
//! pass deliberately asserts almost nothing, because its subject is the ABSENT case. It
//! also skips every GET, since a read cannot violate a foreign key. Neither restriction
//! survives here: a missing grant refuses reads exactly as it refuses writes, and it
//! refuses them at operator-plane routes that hang off no environment at all. So this file
//! drives every operation the committed contract publishes, at whatever the method is, and
//! requires that none of them answers a server error.
//!
//! # Why the completeness of the sweep is itself checked
//!
//! A sweep over a hand-maintained list reports on whatever the list happens to contain.
//! [`every_documented_operation_is_driven_by_a_case`] resolves each case against
//! `docs/openapi/management.json` by method and templated path and fails when the two sets
//! disagree in EITHER direction, so a new operation fails this file the moment it is
//! documented and a case whose path drifts matches no template and fails too. It is the
//! idiom `absent_environment.rs` and `openapi_contract.rs` already use, for the same
//! reason.
//!
//! # Why the fixture is seeded rather than synthesized
//!
//! An id that parses but names no row is answered 404 by the handler's own addressing read,
//! usually before the handler reaches the relation whose grant is in question. A sweep over
//! synthesized ids therefore proves much less than it looks like it does. Every id this
//! file drives names a REAL row, created through the management API itself where a create
//! route exists and seeded through the store where none does, so each case reaches as deep
//! into its handler as an operator's own request would.
//!
//! # Why every optional surface is armed
//!
//! A disabled surface answers the uniform not-found BEFORE it resolves anything, and that
//! refusal is indistinguishable from a clean pass here. [`Harness::start_fully_armed`]
//! turns on the signup-quarantine queue, the recovery-approval queue, the compatibility
//! wizard's issuer registry, the federation runtime, and the outbound verification
//! endpoint in one router, so the sweep's silence about those routes is a measurement
//! rather than an artifact of their being off.
//!
//! # Why the SOFT-DELETED contract lives here too
//!
//! [`every_environment_scoped_write_refuses_a_soft_deleted_environment`] needs exactly the
//! three things above: one of every row the surface addresses, one case per documented
//! operation, and a check that the case list has not drifted from the contract. Building a
//! second copy of all three in a file of its own would be a second inventory to keep in
//! step with the same document, which is the shape of the defect issue #443 is about. It
//! reuses [`Fixture`] and [`all_cases`] instead, filters them to the environment prefix,
//! and drives them at two identically configured routers, one of whose environments has
//! been deleted.
//!
//! What it found is the reason it exists. Issue #451 reported three user writes still
//! landing in a soft-deleted environment. Driven across the whole prefix with everything
//! seeded, the answer was TWENTY SIX of the seventy five documented environment-scoped
//! writes, of which the three it named were three.
//!
//! Two spreads are worth naming, because "twenty six" alone says nothing about how far
//! the defect reached, and the number this note used to carry was neither of them. The
//! twenty six are handled by FOURTEEN modules of this crate (`brand_assets`,
//! `client_admin_grants`, `client_scopes`, `connectors`, `dcr`, `flow_versions`,
//! `invitations`, `locales`, `permissions`, `recovery_approvals`, `resource_servers`,
//! `signup_forms`, `signup_quarantine`, `users`), and they hang off TWELVE URL groups
//! under the environment prefix (`applications`, `brands`, `clients`, `connectors`,
//! `invitations`, `journeys`, `locales`, `permissions`, `recovery-approvals`,
//! `resource-servers`, `signup-quarantine`, `users`). Both counts are MEASURED from the
//! failing table this sweep prints when the fixed handlers are reverted, resolved against
//! the committed contract. The fix and the reasoning live in
//! `crates/ironauth-admin/src/org_context.rs`.
//!
//! # What the soft-deleted sweep compares, which is three things and not one
//!
//! The STATUS of every environment-scoped operation, read and write alike, against the
//! answer the live control gave. The BODY of the subset [`documented_body_contents`]
//! names, because a read that lost its rows and kept its 200 is not an audit and satisfies
//! a status comparison perfectly. And the answer to a MALFORMED body on every JSON-bodied
//! write, because a handler that validates its body before it resolves its parent answers
//! a 400 out of an environment an operator believes is gone, and the well-formed sweep
//! cannot see it. All three found something the other two did not.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use common::{Harness, OPERATOR_TOKEN, bearer};
use ironauth_admin::ApiError;
use ironauth_env::Env;
use ironauth_store::{
    AbuseSubject, AbuseSubjectKind, AuthPath, CorrelationId, MigrationKind, NewMigrationRun,
    NewRecoveryFlow, NewResourceServer, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, Scope,
    SignupQuarantineReason, TokenFormat,
};

/// The COMMITTED management contract, embedded at compile time: the same artifact and the
/// same idiom `absent_environment.rs` and `openapi_contract.rs` use.
const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");

/// The shared bearer the fixture ARMS the outbound verification endpoint with, in the
/// sweep environment's own sealed secret (issue #250). It is not configuration: there is
/// no configuration key for it any more.
const OUTBOUND_TOKEN: &str = "outbound-sweep-token-of-at-least-32-bytes";

/// The smallest byte string the brand-asset upload's MAGIC-BYTE sniff accepts: a RIFF
/// container tagged WEBP. The sniff reads the BYTES and never the declared header.
const RASTER_UPLOAD: &str = "RIFF\0\0\0\0WEBP";

/// The eight-byte preamble of a WebAssembly COMPONENT.
///
/// Enough to satisfy the deploy's structural check, which is all this sweep needs: it asks
/// whether the ENVIRONMENT is fenced, not whether the component links. Valid UTF-8 by luck of
/// the encoding -- `\0asm` then the layer word `0d 00 01 00` -- so it fits the `String` body
/// every other case uses.
const COMPONENT_UPLOAD: &str = "\u{0}asm\u{d}\u{0}\u{1}\u{0}";

/// A fixed, plausible instant for every seeded row, in Unix microseconds.
const SEED_MICROS: i64 = 1_700_000_000_000_000;

/// The password the outbound migration verification case presents, and the plaintext the
/// seeded user's native Argon2id verifier is built over, so that case drives the POSITIVE
/// branch rather than only the negative one.
const MIGRATION_PASSWORD: &str = "hunter2hunter2";

/// A claim value the seeded user's claim document carries and nothing else in this file
/// does, so finding it in a response proves the PROFILE came back rather than an empty
/// object that happened to serialize.
const MIGRATION_CLAIM: &str = "sweep-nickname";

/// A native Argon2id PHC verifier for `password`, exactly what the login path stores for
/// a normally registered user. The same helper, with the same defaults, that
/// `tests/export.rs` seeds its native-credential users with.
fn argon2_hash(password: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"live-surface-seed-salt").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// A valid serialized design-token blob (the typed scalars the branding module validates),
/// for the seeded default brand the four asset routes hang off.
const BRAND_TOKENS_JSON: &str = r##"{"color_bg":"#f5f5f5","color_fg":"#1a1a1a","color_accent":"#2f5bde","color_accent_fg":"#ffffff","color_error":"#b00020","color_surface":"#ffffff","color_border":"#bbbbbb","font_family":"system_ui","radius":6,"space":16}"##;

/// One management operation, addressed at a real resource.
struct Case {
    /// `module.operationId`. The `operationId` half is load bearing: the coverage test
    /// resolves each case against the contract and then requires the label to name the
    /// operation it resolved to, so a label that drifts from the route it drives is a
    /// failure rather than a comment.
    label: &'static str,
    method: &'static str,
    path: String,
    body: Option<String>,
    /// The request content type, for the two octet-stream uploads.
    content_type: &'static str,
    /// The bearer to present. All but one route take the bootstrap operator token; the
    /// outbound verification endpoint authorizes ONLY its own shared credential, so driving
    /// it with the operator token would measure a 401 and nothing else.
    token: &'static str,
}

impl Case {
    fn json(
        label: &'static str,
        method: &'static str,
        path: String,
        body: &serde_json::Value,
    ) -> Self {
        Self {
            label,
            method,
            path,
            body: Some(body.to_string()),
            content_type: "application/json",
            token: OPERATOR_TOKEN,
        }
    }

    fn empty(label: &'static str, method: &'static str, path: String) -> Self {
        Self {
            label,
            method,
            path,
            body: None,
            content_type: "application/json",
            token: OPERATOR_TOKEN,
        }
    }

    /// A newline-delimited record body: the streaming bulk-import job's input format.
    fn ndjson(label: &'static str, path: String, body: &str) -> Self {
        Self {
            label,
            method: "POST",
            path,
            body: Some(body.to_owned()),
            content_type: "application/x-ndjson",
            token: OPERATOR_TOKEN,
        }
    }

    fn raster(label: &'static str, path: String) -> Self {
        Self {
            label,
            method: "PUT",
            path,
            body: Some(RASTER_UPLOAD.to_owned()),
            content_type: "application/octet-stream",
            token: OPERATOR_TOKEN,
        }
    }

    /// Present a bearer other than the operator token.
    fn with_bearer(mut self, token: &'static str) -> Self {
        self.token = token;
        self
    }
}

/// One documented operation, as the committed contract publishes it.
struct DocumentedOperation {
    operation_id: String,
    method: String,
    template: String,
}

/// Every operation the committed contract publishes: the inventory this sweep must cover
/// in full, in both directions.
fn documented_operations() -> Vec<DocumentedOperation> {
    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut operations = Vec::new();
    for (template, methods) in doc["paths"].as_object().expect("paths") {
        for (method, operation) in methods.as_object().expect("operations") {
            operations.push(DocumentedOperation {
                operation_id: operation["operationId"]
                    .as_str()
                    .expect("every operation carries an id")
                    .to_owned(),
                method: method.to_uppercase(),
                template: template.clone(),
            });
        }
    }
    operations
}

/// Whether a CONCRETE request path is addressed by a TEMPLATED document path: the same
/// segment count, with every templated segment either a `{placeholder}` (which matches any
/// one segment) or an exact literal.
fn template_matches(template: &str, path: &str) -> bool {
    // An OpenAPI path template carries no query string, so a concrete path's query is
    // stripped before the segment comparison: it addresses the same template. The
    // bulk-import create is the one case here that carries one, and without this it
    // would match NO template and fail the coverage check rather than resolve.
    let path = path.split('?').next().unwrap_or(path);
    let expected: Vec<&str> = template.split('/').collect();
    let actual: Vec<&str> = path.split('/').collect();
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual.iter())
        .all(|(pattern, segment)| pattern.starts_with('{') || pattern == segment)
}

/// How many PARAMETER segments a template carries. This is the router's precedence key: a
/// path with a static segment where another has a parameter is the MORE specific of the
/// two, and axum's matcher (matchit) ranks static above parameter at every position.
///
/// Without it this file models the router incorrectly wherever a STATIC segment is a
/// sibling of a parameterized one, which is a shape the surface already uses in several
/// places (`.../brands/{slug}/logo` beside `.../brands/{slug}`, and, at the same position
/// rather than a deeper one, `.../trait-schemas/active` beside `.../trait-schemas/{version}`).
/// MEASURED: `GET .../trait-schemas/active` matched BOTH templates, and the sweep reported
/// the case as ambiguous when the router itself is not ambiguous at all. Ranking here makes
/// the sweep's matcher agree with the router rather than with the raw glob.
fn parameter_count(template: &str) -> usize {
    template
        .split('/')
        .filter(|segment| segment.starts_with('{'))
        .count()
}

/// Every id the sweep addresses, each naming a row that genuinely exists.
struct Fixture {
    tenant: String,
    environment: String,
    /// A SECOND tenant, so the destructive operator-plane lifecycle routes (delete,
    /// suspend, resume, restore) never touch the tenant the rest of the sweep runs in.
    doomed_tenant: String,
    /// A SECOND environment under the primary tenant, for `deleteEnvironment`.
    doomed_environment: String,
    operator: String,
    client: String,
    /// A real `ocn_` binding, so the routing-rule create addresses a live target.
    org_connection: String,
    /// A real domain rule, so the verify case addresses a live one (issue #96).
    routing_rule: String,
    /// A LIVE message row, so the resend case answers something OTHER than the uniform
    /// not-found at a live environment. Without it the case is non-discriminating: an absent
    /// message is a 404 at a live environment and a soft-deleted one alike, so driving it
    /// would measure nothing about the fence, which the sweep detects and refuses.
    message: String,
    /// A LIVE grant, so the withdrawal case measures the environment fence rather than
    /// an id that never resolved (issue #102).
    project_grant: String,
    api_key: String,
    /// A real `sva_` principal, so the service-account key cases address a live owner rather
    /// than an id that never resolved (issue #99).
    service_account: String,
    sa_api_key: String,
    /// A live personal access token handle, so the PAT cases address a real one (issue #99).
    pat: String,
    connector: String,
    /// A live log stream, so the dead-letter cases address a real one. With `lgs_absent`
    /// they answer the uniform not-found at a LIVE environment too, and driving them at a
    /// soft-deleted one would measure nothing about the fence.
    log_stream: String,
    /// A live flow target, so the DELETE case addresses a real one. A synthetic `ftg_absent`
    /// does not decode as a scoped id, so the handler answers the uniform not-found at a LIVE
    /// environment too, and driving it at a soft-deleted one would measure nothing.
    flow_target: String,
    webhook_endpoint: String,
    /// A live external assertion issuer, so the enable toggle addresses a REAL trust anchor
    /// (issue #126). A fabricated `xai_absent` does not decode as a scoped id, so the handler
    /// answers the uniform not-found at a LIVE environment too, and this sweep refuses a write
    /// case that cannot succeed: it would measure nothing about the soft-deleted fence.
    external_issuer: String,
    /// A live subject mapping, for the same reason its issuer is live.
    subject_mapping: String,
    family: String,
    recovery_flow: String,
    group: String,
    invitation: String,
    key: String,
    membership: String,
    organization: String,
    permission: String,
    resource_server: String,
    role: String,
    migration_run: String,
    session: String,
    user: String,
    /// A seeded login identifier on the primary user (epic #514), so `removeUserIdentifier`
    /// is driven at a row that EXISTS. Addressed at a fabricated id the route answers the
    /// uniform not-found at a live environment too, and this sweep refuses such a case: a
    /// probe that cannot succeed measures nothing about the soft-deleted fence. The live
    /// pass CONSUMES this row, which is fine, because the soft-deleted pass is refused by
    /// the liveness fence in `resolve_user` before any store call is reached.
    user_identifier: String,
    /// A SECOND user, quarantined at signup, for the review-queue routes (the primary user
    /// is not quarantined, and the queue's own addressing read would answer 404).
    quarantined_user: String,
    /// A THIRD user, also quarantined. The queue's reject and approve each CONSUME the case
    /// they decide, so a single quarantined signup would leave whichever ran second
    /// addressing a decided row and answering 404, which is a masked route rather than a
    /// measured one.
    second_quarantined_user: String,
    /// A user with no membership yet, so the membership create is a 201 rather than the
    /// conflict the already-enrolled primary user produces.
    unenrolled_user: String,
    /// A HELD recovery approval for the reject, and a second for the approve, for the same
    /// consume-once reason.
    recovery_flow_to_reject: String,
    /// An open headless flow, so the flow inspector observes a real one.
    observed_flow: String,
    /// The brand slug a brand row was created under, so the four asset routes address a
    /// brand that exists.
    brand_slug: String,
    /// The environment's own exported config snapshot, which is exactly the document the
    /// promotion plan and apply take as their source. Without it both are a 400 that never
    /// reaches the config relations they exist to read.
    snapshot: String,
    /// The target's promotable-config revision, as the plan over `snapshot` reported it.
    base_revision: String,
    flow_version: i64,
    /// The activated trait-schema version, so the registry reads address a real row.
    trait_schema_version: i64,
}

/// Read a JSON field out of a response body, failing loudly with the body when it is
/// absent (a seeding step that silently returned an error page is the most expensive way
/// for this file to go quiet).
fn field(body: &str, pointer: &str, what: &str) -> String {
    let value: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|_| panic!("{what}: not JSON: {body}"));
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{what}: no {pointer} in {body}"))
        .to_owned()
}

impl Fixture {
    /// Seed one of everything the surface addresses.
    #[allow(clippy::too_many_lines)]
    async fn seed(h: &Harness) -> Self {
        let env = Env::system();
        let scope = h.outbound_scope();
        let tenant = scope.tenant().to_string();
        let environment = scope.environment().to_string();
        let base = format!("/v1/tenants/{tenant}/environments/{environment}");

        // The operator-plane lifecycle routes are destructive, so they get their own
        // tenant and their own spare environment.
        let (doomed_tenant, _) = h.create_tenant("doomed", "seed-doomed-tenant").await;
        let doomed_environment = h
            .create_environment(&tenant, "doomed", "seed-doomed-env")
            .await;

        let (status, _, body) = h.get("/v1/operators").await;
        assert_eq!(status, StatusCode::OK, "list operators: {body}");
        let operator = field(&body, "/items/0/id", "seed operator");

        // The user carries a REAL native Argon2id verifier and a REAL claim document, and
        // both are load bearing rather than decoration. `verifyMigrationCredential` is one
        // of the two documented write exceptions below, and the branch that exemption is
        // ABOUT is the positive one: a successor draining a decommissioned environment
        // reads back the subject and the profile. Seeded with no password the case drove
        // only the negative branch (MEASURED at a soft-deleted environment:
        // `{"verified":false}`), so the exemption was pinned by a status code over a code
        // path that returns nothing and reads no PII.
        let (status, _, body) = h
            .post(
                &format!("{base}/users"),
                "seed-user",
                &serde_json::json!({
                    "identifier": "sweep@example.test",
                    "password_hash": argon2_hash(MIGRATION_PASSWORD),
                    "claims": { "nickname": MIGRATION_CLAIM },
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create user: {body}");
        let user = field(&body, "/id", "seed user");

        // A login identifier on that user (epic #514), so `removeUserIdentifier` addresses
        // a row that EXISTS. Without it the case answers the uniform not-found at a LIVE
        // environment too, and this sweep rejects such a case outright rather than letting
        // it look covered: a probe that cannot succeed measures nothing about the fence.
        let (status, _, body) = h
            .post(
                &format!("{base}/users/{user}/identifiers"),
                "seed-user-identifier",
                &serde_json::json!({ "type": "email", "value": "sweep-identifier@example.test" })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed identifier: {body}");
        let user_identifier = field(&body, "/id", "seed user identifier");

        let (status, _, body) = h
            .post(
                &format!("{base}/organizations"),
                "seed-org",
                &serde_json::json!({ "display_name": "Sweep" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create organization: {body}");
        let organization = field(&body, "/id", "seed organization");

        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/roles"),
                "seed-role",
                &serde_json::json!({ "slug": "sweep", "display_name": "Sweep" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create org role: {body}");
        let role = field(&body, "/id", "seed role");

        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/groups"),
                "seed-group",
                &serde_json::json!({ "slug": "sweep", "display_name": "Sweep" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create org group: {body}");
        let group = field(&body, "/id", "seed group");

        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/memberships"),
                "seed-membership",
                &serde_json::json!({ "user_id": user }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create membership: {body}");
        let membership = field(&body, "/id", "seed membership");

        let (status, _, body) = h
            .post(
                &format!("{base}/permissions"),
                "seed-permission",
                &serde_json::json!({ "slug": "sweep.read", "display_name": "Sweep" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create permission: {body}");
        let permission = field(&body, "/id", "seed permission");

        let (status, _, body) = h
            .post(
                &format!("{base}/invitations"),
                "seed-invitation",
                &serde_json::json!({ "identifier": "invited@example.test" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create invitation: {body}");
        let invitation = field(&body, "/invitation/id", "seed invitation");

        let (status, _, body) = h
            .post(
                &format!("{base}/connectors"),
                "seed-connector",
                &serde_json::json!({
                    "connector_id": "sweep-connector",
                    "display_name": "Sweep",
                    "protocol": "oidc",
                    "endpoints": { "issuer": "https://idp.example" },
                    "scopes": ["openid"],
                    "client_id": "abc",
                    "client_secret": "shhh"
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create connector: {body}");
        let connector = field(&body, "/id", "seed connector");

        // A real org connection, so the routing-rule create addresses a target that
        // EXISTS. A synthetic one answers the uniform not-found at a live environment
        // too, which would make driving it at a soft-deleted one measure nothing.
        let org_connection = ironauth_store::OrgConnectionId::generate(&env, &scope);
        h.db()
            .control_store()
            .scoped(scope)
            .acting(h.db().test_actor(&env), CorrelationId::generate(&env))
            .org_connections()
            .create(
                &env,
                &org_connection,
                1_000_000,
                ironauth_store::NewOrgConnection {
                    organization_id: &ironauth_store::OrganizationId::parse_in_scope(
                        &organization,
                        &scope,
                    )
                    .expect("the seeded organization id"),
                    connector_id: &ironauth_store::ConnectorId::parse_in_scope(&connector, &scope)
                        .expect("the seeded connector id"),
                    overlay_min_acr: None,
                    max_age_secs: None,
                    overlay_min_class: None,
                    capture_upstream_tokens: false,
                    enabled: true,
                },
            )
            .await
            .expect("seed org connection");
        let org_connection = org_connection.to_string();

        // A real domain rule, so the verify case addresses one that EXISTS. A synthetic
        // id is the uniform not-found at a live environment too, which would make
        // driving it at a soft-deleted one measure nothing.
        let (status, _, body) = h
            .post(
                &format!("{base}/routing-rules"),
                "seed-routing-rule",
                &serde_json::json!({
                    "kind": "domain",
                    "value": "sweep-seed.example",
                    "org_connection_id": org_connection,
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create routing rule: {body}");
        let routing_rule = field(&body, "/id", "seed routing rule");

        // A real endpoint, so the delete case addresses an id that PARSES in this scope.
        // A synthetic one is the uniform not-found at a live environment too, which would
        // make driving it at a soft-deleted one measure nothing about the fence.
        let (status, _, body) = h
            .post(
                &format!("{base}/webhook-endpoints"),
                "seed-webhook",
                &serde_json::json!({ "url": "https://example.test/hook" }).to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create webhook endpoint: {body}"
        );
        let webhook_endpoint = field(&body, "/id", "seed webhook endpoint");

        // A live log stream, so the dead-letter cases address a real one. Without it they
        // answer the uniform not-found at a LIVE environment as well, and the soft-deleted
        // sweep says so by name rather than passing on a case that measures nothing.
        let (status, _, body) = h
            .post(
                &format!("{base}/log-streams"),
                "seed-log-stream",
                &serde_json::json!({
                    "source": "both",
                    "sink_type": "http",
                    "sink_config": {"endpoint": "https://sink.example/in"},
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed log stream: {body}");
        let log_stream = field(&body, "/id", "seed log stream");

        // A live flow target, so the DELETE case addresses a REAL row. A synthetic id like
        // `ftg_absent` does not decode as a scoped id, so the handler answers the uniform
        // not-found at a LIVE environment too, and driving it at a soft-deleted one would
        // measure nothing about the fence. That is this file's own rule, stated in its
        // header, and the log-stream idiom it was copied from only works because that delete
        // takes a bare string and never parses it.
        let (status, _, body) = h
            .post(
                &format!("{base}/flow-targets"),
                "seed-flow-target",
                &serde_json::json!({
                    "name": "live-surface-seed",
                    "target_class": "request",
                    "invocation": "sync",
                    "timing": "pre_persist",
                    "endpoint": "https://target.example/check",
                    "timeout_ms": 500,
                    "failure_policy": "fail_closed",
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed flow target: {body}");
        let flow_target = field(&body, "/id", "seed flow target");

        let (status, _, body) = h
            .post(
                &format!("{base}/keys"),
                "seed-key",
                &serde_json::json!({ "display_name": "Sweep" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create management key: {body}");
        let key = field(&body, "/id", "seed management key");

        let (status, _, body) = h
            .put(
                &format!("{base}/locales/en"),
                &serde_json::json!({ "entries": { "1010001": "Sign in" } }).to_string(),
            )
            .await;
        assert!(status.is_success(), "set locale: {status} {body}");

        let (status, _, body) = h
            .post(
                &format!("{base}/dcr/policies"),
                "seed-dcr-policy",
                &serde_json::json!({ "name": "sweep", "primitives": [] }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create dcr policy: {body}");

        let (status, _, body) = h
            .post(
                &format!("{base}/journeys/login/versions"),
                "seed-flow-version",
                &serde_json::json!({
            "artifact": {
                "schema_version": "ironauth.journey/v1",
                "id": "login",
                "engine_version": 1,
                "entry": "primary",
                "steps": [
                    {"id": "primary", "kind": "identifier_password", "node_group": "password"},
                    {"id": "done", "kind": "terminal"}
                ],
                "transitions": [{"from": "primary", "to": "done"}]
            }
        }).to_string(),
            )
            .await;
        assert!(status.is_success(), "create flow version: {status} {body}");
        let flow_version = serde_json::from_str::<serde_json::Value>(&body)
            .expect("flow version json")
            .pointer("/version")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("no /version in {body}"));

        // A trait-schema version, ACTIVATED, so the active read, the by-version read, and
        // the activation all address a real row (issue #53). Reach, not verdict: a 404
        // would not be a server error, but it would also never touch the `trait_schemas`
        // relation this sweep exists to prove the control role can reach.
        let (status, _, body) = h
            .post(
                &format!("{base}/trait-schemas"),
                "seed-trait-schema",
                &serde_json::json!({ "schema": {"type": "object"} }).to_string(),
            )
            .await;
        assert!(status.is_success(), "create trait schema: {status} {body}");
        let trait_schema_version = serde_json::from_str::<serde_json::Value>(&body)
            .expect("trait schema json")
            .pointer("/version")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("no /version in {body}"));
        let (status, _, body) = h
            .post(
                &format!("{base}/trait-schemas/{trait_schema_version}/activate"),
                "seed-trait-schema-activate",
                "",
            )
            .await;
        assert!(
            status.is_success(),
            "activate trait schema: {status} {body}"
        );

        // Every day-one algorithm, so the compatibility wizard resolves this issuer as
        // fully provisioned and the signing-algorithm pin reaches its write.
        h.provision_all_algorithms(scope).await;

        // The data-plane rows the management surface can read and revoke but never mint:
        // a dynamically registered client, a live session, and its refresh family.
        let client = h.seed_quarantined_dcr_client(scope).await.to_string();

        // A LIVE project grant (issue #102). The withdrawal case must address a grant
        // that really resolves: with an unresolvable id it answers the uniform not-found
        // at a LIVE environment too, and driving that at a soft-deleted one measures
        // nothing about the environment fence. This harness caught exactly that.
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/project-grants"),
                "seed-project-grant",
                &serde_json::json!({ "client_id": client, "role_ids": [&role] }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create project grant: {body}");
        let project_grant = field(&body, "/id", "seed project grant");
        // A REAL key, for the same reason as the grant above: revoking a handle that does
        // not exist answers the uniform not-found at a LIVE environment too, so driving that
        // at a soft-deleted one measures nothing about the fence. The sweep caught exactly
        // that when this case first used a bogus handle.
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations/{organization}/api-keys"),
                "seed-api-key",
                &serde_json::json!({ "display_name": "sweep key" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create api key: {body}");
        let api_key = field(&body, "/id", "seed api key");
        let session = h.seed_session(scope, &user).await;
        let family = h
            .seed_refresh_family(scope, &user, &client, &session, false)
            .await
            .to_string();
        let session = session.to_string();

        let actor = h.test_actor(&env);

        // A service account, and one key on it. The principal is minted through the store
        // because it has no create route of its own: it is minted for a CLIENT, the way the
        // client-credentials grant does it at first issuance.
        let service_account = h
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .service_accounts()
            .ensure(
                &env,
                &ironauth_store::ClientId::parse_in_scope(&client, &scope).expect("client id"),
            )
            .await
            .expect("mint the service-account principal")
            .to_string();
        let sa_base = format!("{base}/service-accounts/{service_account}/api-keys");
        let (status, _, body) = h
            .post(
                &sa_base,
                "seed-sa-api-key",
                &serde_json::json!({ "display_name": "sweep machine key" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create sa api key: {body}");
        let sa_api_key = field(&body, "/id", "seed sa api key");

        // A live trust anchor and a live mapping off it (issue #126). The mapping names the
        // issuer STRING rather than the row id, which is why the two resources are siblings on
        // the surface rather than nested. Seeded AFTER the service account, because a mapping
        // is refused unless its principal names a machine identity that exists.
        let seed_issuer = "https://token.actions.githubusercontent.com";
        let (status, _, body) = h
            .post(
                &format!("{base}/external-issuers"),
                "seed-external-issuer",
                &serde_json::json!({
                    "issuer": seed_issuer,
                    "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed external issuer: {body}");
        let external_issuer = field(&body, "/id", "seed external issuer");

        let (status, _, body) = h
            .post(
                &format!("{base}/subject-mappings"),
                "seed-subject-mapping",
                &serde_json::json!({
                    "issuer": seed_issuer,
                    "external_subject": "repo:acme/live-surface:ref:refs/heads/main",
                    "principal": &service_account,
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed subject mapping: {body}");
        let subject_mapping = field(&body, "/id", "seed subject mapping");
        let pat_base = format!("{base}/users/{user}/personal-access-tokens");
        let (status, _, body) = h
            .post(
                &pat_base,
                "seed-pat",
                &serde_json::json!({ "display_name": "sweep pat" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create pat: {body}");
        let pat = field(&body, "/id", "seed pat");

        // A remembered CONSENT from the seeded user to the seeded client, so
        // `listUserConsents` answers with a ROW. The read half of the soft-deleted
        // contract below compares the BODY for this case, and an empty 200 is not an
        // audit: with no consent seeded the list was structurally empty, and
        // `consents::list_user_consents` returning `Vec::new()` outright left the whole
        // soft-deleted sweep GREEN along with `tests/consents.rs`, `tests/users.rs` and
        // `tests/deleted_environment.rs` (MEASURED). The client's consent mode is the
        // default `explicit`, so the grant is not filtered out as an auto-grant.
        h.store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .consents()
            .grant(&env, &user, &client, Some("openid"))
            .await
            .expect("seed a remembered consent");

        // A declarative claim mapping (issue #113), seeded rather than left to the sweep's own
        // PUT case.
        //
        // The read sweep compares a soft-deleted environment's answer against a LIVE control
        // harness, and the control drives every case in order -- so a GET that depends on the
        // PUT beside it answers 200 at the control and 404 at the doomed environment, where the
        // PUT was correctly refused. That difference is the fixture, not the fence.
        //
        // `getClaimsMapping` is 404 when no mapping is installed, deliberately: "no mapping"
        // and "an empty mapping" produce opposite tokens, so a 200 carrying an empty rule list
        // would report one as the other. Seeding is what makes both environments hold the same
        // state, which is the only condition under which the comparison measures the fence.
        // The CONTROL store: `claims_mappings` grants the data plane SELECT and nothing more,
        // deliberately, so seeding through `h.store()` is a permission-denied rather than a
        // seed. That refusal is the grant split working.
        h.control_store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .claims_mappings()
            .set(
                &env,
                &ironauth_store::ClientId::parse_in_scope(&client, &scope).expect("client id"),
                r#"[{"kind":"static","name":"tier","value":"gold"}]"#,
            )
            .await
            .expect("seed a claim mapping");

        // A WASM token hook (issue #114), seeded for exactly the reason the claim mapping above
        // is: `getTokenHook` is 404 when no hook is deployed, so a GET that depended on the PUT
        // beside it would answer 200 at the live control and 404 at the doomed environment,
        // where the PUT was correctly refused -- and that difference is the fixture, not the
        // fence. Seeding both environments is the only condition under which the comparison
        // measures anything.
        //
        // Eight bytes: a component preamble and nothing else. The sweep asks whether the
        // ENVIRONMENT is fenced, and a component that could be refused on its own contents
        // would answer a different question.
        //
        // The CONTROL store again, because `token_hooks` grants the data plane SELECT and
        // nothing more.
        h.control_store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .token_hooks()
            .set(
                &env,
                &ironauth_store::ClientId::parse_in_scope(&client, &scope).expect("client id"),
                b"\0asm\x0d\0\x01\0",
                1,
            )
            .await
            .expect("seed a token hook");

        // A quarantined signup for the fraud-review queue.
        let quarantined_user = h
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .users()
            .register_quarantined(
                &env,
                "risky@example.test",
                "$argon2id$dummy",
                SignupQuarantineReason::RiskOutput,
                None,
            )
            .await
            .expect("seed a quarantined signup")
            .to_string();

        // A SECOND quarantined signup. Reject and approve each CONSUME the case they
        // decide, so with one seeded case whichever ran second addressed a decided row and
        // answered 404 (measured), which is a masked route rather than a passing one.
        let second_quarantined_user = h
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .users()
            .register_quarantined(
                &env,
                "risky2@example.test",
                "$argon2id$dummy",
                SignupQuarantineReason::RiskOutput,
                None,
            )
            .await
            .expect("seed a second quarantined signup")
            .to_string();

        // A user with no membership yet: the primary user is already enrolled, so the
        // membership create driven at it is a 409 that never reaches the insert.
        let (status, _, body) = h
            .post(
                &format!("{base}/users"),
                "seed-unenrolled-user",
                &serde_json::json!({ "identifier": "unenrolled@example.test" }).to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create unenrolled user: {body}"
        );
        let unenrolled_user = field(&body, "/id", "seed unenrolled user");

        // TWO held admin-approved recovery flows, each with its pending approval: the shape
        // the recovery review queue decides. Two for the same consume-once reason as the
        // quarantine queue above, so reject and approve each get their own case.
        let subject = ironauth_store::UserId::parse_in_scope(&user, &scope)
            .expect("the seeded user id parses in scope");
        let mut held = Vec::new();
        for (nonce, recipient) in [
            (7_u8, "recover@example.test"),
            (8_u8, "recover2@example.test"),
        ] {
            let id = RecoveryFlowId::generate(&env, &scope);
            h.store()
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .recovery_flows()
                .initiate(
                    &env,
                    NewRecoveryFlow {
                        id: &id,
                        subject: &subject,
                        entry_point: RecoveryEntryPoint::LostAllFactors,
                        recover_acr: "urn:ironauth:acr:pwd",
                        cancel_token_digest: &[nonce; 32],
                        recipient,
                        hold_until_unix_micros: Some(0),
                        method: RecoveryMethod::AdminApproved,
                    },
                    0,
                )
                .await
                .expect("seed the recovery flow");
            h.store()
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .recovery_approvals()
                .open(&env, &id, &subject)
                .await
                .expect("open the pending approval");
            held.push(id.to_string());
        }
        let recovery_flow_to_reject = held.remove(0);
        let recovery_flow = held.remove(0);

        // A resource server: the surface reads and patches one, but publishes no create
        // route, so it is registered through the control plane exactly as provisioning
        // does.
        let resource_server_id = ironauth_store::ResourceServerId::generate(&env, &scope);
        h.control_store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .resource_servers()
            .register(
                &env,
                NewResourceServer {
                    id: &resource_server_id,
                    audience: "https://api.sweep.test",
                    token_format: TokenFormat::AtJwt,
                    access_token_ttl_secs: None,
                },
            )
            .await
            .expect("register a resource server");

        // A migration run, for the run listing and its violation page. Runs are recorded
        // by the importer through the data plane, not minted by this surface.
        let migration_run = h
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .migration_runs()
            .create(
                &env,
                NewMigrationRun {
                    kind: MigrationKind::BulkImport,
                    source_total: 1,
                    backfill_expected: 0,
                    subject_ref: None,
                },
                SEED_MICROS,
            )
            .await
            .expect("seed a migration run")
            .to_string();

        // An MDS3 cache row, so the WebAuthn metadata health read has something to
        // report rather than only the empty-cache branch.
        h.store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .mds3_blob_cache()
            .upsert(
                &env,
                5,
                1,
                &serde_json::json!({ "no": 5, "entries": [] }),
                b"digest-5",
                SEED_MICROS,
                SEED_MICROS,
            )
            .await
            .expect("seed the mds3 blob cache");

        // The per-client admin consent grant and the signup form. Both are addressed by a
        // DELETE case, and both used to be created by the PUT case that runs before it, so
        // in a pass where the PUT is refused the DELETE addressed a row that was never
        // there and answered 404 for a reason that had nothing to do with the environment.
        // A sweep cannot tell that apart from a fence, so the rows are SEEDED here and the
        // deletes are discriminating in both passes.
        let (status, _, body) = h
            .put(
                &format!("{base}/applications/{client}/admin-consent"),
                &serde_json::json!({ "scope": "openid" }).to_string(),
            )
            .await;
        assert!(status.is_success(), "seed admin consent: {status} {body}");
        let (status, _, body) = h
            .put(
                &format!("{base}/applications/{client}/signup-form"),
                &serde_json::json!({ "fields": [] }).to_string(),
            )
            .await;
        assert!(status.is_success(), "seed signup form: {status} {body}");

        // A variable for the read half of the variable surface (issue #235). `getVariable`
        // answers the uniform not-found when the name does not exist, so without a seeded row
        // the read case would be driven at a 404 for an ORDINARY absent-resource reason and
        // would measure nothing about environment liveness, which is what this sweep exists
        // to compare.
        let (status, _, body) = h
            .put_with_key(
                &format!("{base}/variables/LIVE_SURFACE_PROBE"),
                "k-seed-variable",
                &serde_json::json!({ "value": "seeded" }).to_string(),
            )
            .await;
        assert!(status.is_success(), "seed variable: {status} {body}");

        // A secret, for the same reason and through the same surface (issue #235). The seed
        // goes through the API rather than the store so it exercises the cross-role write
        // path: if the data-plane seam this module depends on were not installed, this seed
        // would fail here rather than leaving the read cases quietly driven at a 404.
        let (status, _, body) = h
            .put_with_key(
                &format!("{base}/secrets/LIVE_SURFACE_PROBE"),
                "k-seed-secret",
                &serde_json::json!({ "value": "seeded" }).to_string(),
            )
            .await;
        assert!(status.is_success(), "seed secret: {status} {body}");

        // A DEFAULT brand. The four brand-asset routes address a brand by slug and answer
        // 404 when none exists, and no management route creates one, so without this the
        // whole asset surface is driven at a 404 and measured by nothing.
        h.control_store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .brands()
            .set(
                &env,
                &ironauth_store::BrandId::generate(&env, &scope),
                SEED_MICROS,
                ironauth_store::NewBrand {
                    slug: "default",
                    is_default: true,
                    product_name: "Sweep",
                    show_wordmark: true,
                    brand_token: None,
                    tokens_json: BRAND_TOKENS_JSON,
                    tokens_dark_json: None,
                    slots_json: "{}",
                    host_pattern: None,
                    client_id: None,
                },
            )
            .await
            .expect("seed the default brand");

        // And its LOGO and FAVICON. Same reason as the admin consent and the signup form
        // above, and this one was found by mutation rather than by reading: with the two
        // assets created only by the upload CASE, a pass in which the upload is refused
        // leaves the two DELETE cases addressing an asset that was never there, and
        // removing the fence from `brand_assets::delete_asset` outright left the whole
        // soft-deleted sweep GREEN (measured). Seeding the assets is what makes the two
        // deletes discriminating, and it is why the live answer alone is not a sufficient
        // anti-vacuity control: at a live environment the upload runs first, so the delete
        // answers 204 there either way.
        for kind in ["logo", "favicon"] {
            let request = Request::builder()
                .method("PUT")
                .uri(format!("{base}/brands/default/{kind}"))
                .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(RASTER_UPLOAD))
                .expect("request builds");
            let (status, _, body) = h.send(request).await;
            assert!(status.is_success(), "seed brand {kind}: {status} {body}");
        }

        // An open headless flow, so the flow inspector's observation read resolves a row
        // instead of stopping at its own not-found.
        let observed_flow = ironauth_store::FlowId::generate(&env, &scope);
        h.store()
            .scoped(scope)
            .flows()
            .create(
                &observed_flow,
                ironauth_store::NewFlow {
                    journey: "login",
                    transport: "api",
                    // The serialized PersistedState at the login start state. An EMPTY
                    // object does not deserialize into one, and the inspector maps a
                    // malformed row to the uniform not-found, so a `{}` state produced a
                    // 404 that looked exactly like a missing row (measured).
                    state: "{\"step\":\"identifier_password\"}",
                    submit_token: "sweep-submit-token",
                    transient_payload: None,
                    return_to: None,
                    contract_version: 1,
                    flow_version_id: None,
                    expires_at_unix_micros: 4_102_444_800_000_000,
                },
            )
            .await
            .expect("seed an open flow");

        // A ban placed through the DATA plane, so the ban LIST and LIFT address a real
        // row rather than an empty relation. The management plane's own ability to place
        // one is what the sweep measures.
        h.store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(&env))
            .abuse()
            .ban(
                &env,
                ironauth_store::NewBan {
                    id: &ironauth_store::AbuseBanId::generate(&env, &scope),
                    subject: &AbuseSubject::ip("198.51.100.9"),
                    auth_path: AuthPath::Passkey,
                    reason: "seeded by the data plane",
                    expires_at_unix_micros: None,
                },
                SEED_MICROS,
                None,
            )
            .await
            .expect("seed an abuse ban");

        // The environment's OWN exported config snapshot, and the plan over it. This is
        // what the promotion routes take as their source: driven with a synthesized body
        // both are a 400 that never reaches the fourteen relations a snapshot reads, so
        // the deepest read fan-out on the whole surface would go unmeasured. Promoting an
        // environment onto ITSELF is a legitimate no-op plan, and a no-op is exactly what
        // a sweep wants: it exercises every read and changes nothing.
        let (status, _, snapshot) = h.get(&format!("{base}/config/snapshot")).await;
        assert_eq!(status, StatusCode::OK, "export the snapshot: {snapshot}");
        let (status, _, plan) = h
            .post(
                &format!("{base}/config/promotion/plan"),
                "seed-plan",
                &snapshot,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "plan the promotion: {plan}");
        let base_revision = field(&plan, "/base_revision", "seed plan base revision");

        // A LIVE message row, so the resend case answers something other than the uniform
        // not-found at a live environment. Inserted directly rather than through `enqueue`:
        // the row is the fixture, and enqueue would additionally need provisioned envelope
        // keys and a sealed recipient that nothing here reads. `resend` refuses it (there is
        // no delivery job to re-queue), and a REFUSAL is a discriminating answer -- 200 with a
        // reason at a live environment, the uniform 404 at a soft-deleted one.
        // GENERATED for the scope, not synthesized: a `msg_` identifier embeds its (tenant,
        // environment) and the handler parses it IN SCOPE, so a hand-built string is refused
        // at the parse and the case goes back to answering the uniform not-found.
        let message = ironauth_store::MessageId::generate(&env, &scope).to_string();
        sqlx::query(
            "INSERT INTO messages \
             (id, tenant_id, environment_id, kind, recipient_bidx, dedup_key) \
             VALUES ($1, $2, $3, 'email_otp', $4, $5)",
        )
        .bind(&message)
        .bind(&tenant)
        .bind(&environment)
        .bind(vec![0x11_u8; 32])
        .bind(format!("seed-{message}"))
        .execute(h.db().owner_pool())
        .await
        .expect("seed a message row");

        Self {
            tenant,
            environment,
            message,
            org_connection,
            routing_rule,
            project_grant,
            api_key,
            service_account,
            sa_api_key,
            pat,
            doomed_tenant,
            doomed_environment,
            operator,
            client,
            connector,
            log_stream,
            flow_target,
            webhook_endpoint,
            external_issuer,
            subject_mapping,
            family,
            recovery_flow,
            recovery_flow_to_reject,
            observed_flow: observed_flow.to_string(),
            brand_slug: "default".to_owned(),
            snapshot,
            base_revision,
            second_quarantined_user,
            unenrolled_user,
            group,
            invitation,
            key,
            membership,
            organization,
            permission,
            resource_server: resource_server_id.to_string(),
            role,
            migration_run,
            session,
            user,
            user_identifier,
            quarantined_user,
            flow_version,
            trait_schema_version,
        }
    }
}

/// Every documented operation, addressed at the seeded fixture.
///
/// The order is load bearing in exactly one way: a DELETE removes the row later cases
/// address, so the destructive cases for each resource family come last within that
/// family. A case that lands after its resource is gone answers 404, which is not a server
/// error, so the ordering protects the sweep's REACH rather than its verdict.
#[allow(clippy::too_many_lines)]
fn all_cases(f: &Fixture) -> Vec<Case> {
    let Fixture {
        tenant,
        environment,
        doomed_tenant,
        doomed_environment,
        operator,
        client,
        message,
        org_connection,
        routing_rule,
        project_grant,
        api_key,
        service_account,
        sa_api_key,
        pat,
        connector,
        log_stream,
        flow_target,
        webhook_endpoint,
        external_issuer,
        subject_mapping,
        family,
        recovery_flow,
        group,
        invitation,
        key,
        membership,
        organization,
        permission,
        resource_server,
        role,
        migration_run,
        session,
        user,
        user_identifier,
        quarantined_user,
        second_quarantined_user,
        unenrolled_user,
        recovery_flow_to_reject,
        observed_flow,
        brand_slug,
        snapshot,
        base_revision,
        flow_version,
        trait_schema_version,
    } = f;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org_base = format!("{base}/organizations/{organization}");
    let sa_base = format!("{base}/service-accounts/{service_account}/api-keys");
    let pat_base = format!("{base}/users/{user}/personal-access-tokens");
    let role_ref = serde_json::json!({ "role_id": role });
    let ban = serde_json::json!({
        "subject_kind": "ip", "subject": "203.0.113.7", "auth_path": "password"
    });

    vec![
        // ---- the operator plane, which hangs off no environment ----
        Case::empty(
            "signing_interop.getSigningRecommendations",
            "GET",
            "/v1/interop/signing-recommendations".to_owned(),
        ),
        Case::empty("operators.listOperators", "GET", "/v1/operators".to_owned()),
        Case::empty(
            "operators.getOperator",
            "GET",
            format!("/v1/operators/{operator}"),
        ),
        Case::empty(
            "resource_types.listResourceTypes",
            "GET",
            "/v1/resource-types".to_owned(),
        ),
        Case::empty("tenants.listTenants", "GET", "/v1/tenants".to_owned()),
        Case::json(
            "tenants.createTenant",
            "POST",
            "/v1/tenants".to_owned(),
            &serde_json::json!({ "display_name": "Sweep created" }),
        ),
        Case::empty("tenants.getTenant", "GET", format!("/v1/tenants/{tenant}")),
        Case::empty(
            "environments.listEnvironments",
            "GET",
            format!("/v1/tenants/{tenant}/environments"),
        ),
        Case::json(
            "environments.createEnvironment",
            "POST",
            format!("/v1/tenants/{tenant}/environments"),
            &serde_json::json!({ "display_name": "Sweep created", "kind": "dev" }),
        ),
        Case::empty("environments.getEnvironment", "GET", base.clone()),
        // ---- credential-abuse bans: the reported instance ----
        Case::empty("bans.listBans", "GET", format!("{base}/abuse/bans")),
        Case::json(
            "bans.createBan",
            "POST",
            format!("{base}/abuse/bans"),
            &ban.clone(),
        ),
        Case::json(
            "bans.liftBan",
            "POST",
            format!("{base}/abuse/bans/lift"),
            &ban,
        ),
        // ---- Standard Webhooks endpoint registration (issue #105) ----
        // ---- async queue depth (issue #104) ----
        Case::empty(
            "queues.listQueueDepths",
            "GET",
            format!("{base}/queues"),
        ),
        // ---- HTTP flow targets (issue #112) ----
        Case::empty(
            "flow_targets.listFlowTargets",
            "GET",
            format!("{base}/flow-targets"),
        ),
        Case::json(
            "flow_targets.createFlowTarget",
            "POST",
            format!("{base}/flow-targets"),
            &serde_json::json!({"name": "live-surface-probe", "target_class": "request",
                               "invocation": "sync", "timing": "pre_persist",
                               "endpoint": "https://target.example/check",
                               "timeout_ms": 500, "failure_policy": "fail_closed"}),
        ),
        Case::empty(
            "flow_targets.listFlowTargetDeadLetters",
            "GET",
            format!("{base}/flow-targets/{flow_target}/dead-letters"),
        ),
        Case::json(
            "flow_targets.replayFlowTargetDeadLetters",
            "POST",
            format!("{base}/flow-targets/{flow_target}/replay"),
            &serde_json::json!({}),
        ),
        // The DELETE comes last of the flow-target cases deliberately: it deregisters the very
        // target the two above address, and a soft-deleted target is a uniform not-found to
        // the replay route.
        Case::empty(
            "flow_targets.deleteFlowTarget",
            "DELETE",
            format!("{base}/flow-targets/{flow_target}"),
        ),

        // ---- External assertion trust anchors and subject mappings (issue #126) ----
        //
        // Both enable toggles run after the reads and the creates, and disable rather than
        // enable: they address rows the two listings above have already been driven at, and a
        // disable is the direction an operator reaches for under compromise. The two DELETES
        // are last of all, because they consume the rows every case here addresses.
        Case::empty(
            "external_issuers.listExternalIssuers",
            "GET",
            format!("{base}/external-issuers"),
        ),
        Case::json(
            "external_issuers.registerExternalIssuer",
            "POST",
            format!("{base}/external-issuers"),
            // A DIFFERENT issuer than the seeded one: `(tenant, environment, issuer)` is
            // unique, so re-registering the seeded string would answer a conflict at a LIVE
            // environment and this sweep would be measuring the constraint, not the fence.
            &serde_json::json!({
                "issuer": "https://live-surface.example/oidc",
                "jwks_uri": "https://live-surface.example/oauth/discovery/keys",
            }),
        ),
        Case::empty(
            "external_issuers.listSubjectMappings",
            "GET",
            format!("{base}/subject-mappings"),
        ),
        Case::json(
            "external_issuers.createSubjectMapping",
            "POST",
            format!("{base}/subject-mappings"),
            // Unique on `(issuer, external_subject)`, so this differs from the seeded rule in
            // its subject for the same reason the registration above differs in its issuer.
            &serde_json::json!({
                "issuer": "https://token.actions.githubusercontent.com",
                "external_subject": "repo:acme/live-surface:ref:refs/heads/release",
                "principal": service_account,
            }),
        ),
        Case::json(
            "external_issuers.setExternalIssuerEnabled",
            "PATCH",
            format!("{base}/external-issuers/{external_issuer}"),
            &serde_json::json!({ "enabled": false }),
        ),
        Case::json(
            "external_issuers.setSubjectMappingEnabled",
            "PATCH",
            format!("{base}/subject-mappings/{subject_mapping}"),
            &serde_json::json!({ "enabled": false }),
        ),
        // The two deletes run LAST of this family, because they CONSUME the rows every case
        // above addresses. They are what makes a mis-registration correctable: both unique
        // constraints ignore `enabled`, so a parked row keeps its natural key and re-registering
        // the same issuer would answer 409 forever (issue #126, migration 0153).
        Case::empty(
            "external_issuers.deleteSubjectMapping",
            "DELETE",
            format!("{base}/subject-mappings/{subject_mapping}"),
        ),
        Case::empty(
            "external_issuers.deleteExternalIssuer",
            "DELETE",
            format!("{base}/external-issuers/{external_issuer}"),
        ),
        // ---- SIEM log streams (issue #110) ----
        Case::empty(
            "log_streams.listLogStreams",
            "GET",
            format!("{base}/log-streams"),
        ),
        // One message's delivery status (issue #111 criterion 1), at the SEEDED message, so
        // the sweep reaches the handler's body rather than stopping at the identifier parse.
        // What it returns is asserted in `delegated_admin.rs`; this drives the route.
        Case::empty(
            "messages.getMessageStatus",
            "GET",
            format!("{base}/messages/{message}"),
        ),
        // The resend WRITE, at the same seeded message. Its live answer is a 200 carrying
        // `payload_expired` -- the seeded row has no delivery job to re-queue -- and that is
        // what makes it discriminating against the soft-deleted environment's uniform 404.
        Case::empty(
            "messages.resendMessage",
            "POST",
            format!("{base}/messages/{message}/resend"),
        ),
        Case::json(
            "log_streams.createLogStream",
            "POST",
            format!("{base}/log-streams"),
            &serde_json::json!({"source": "both", "sink_type": "http",
                               "sink_config": {"endpoint": "https://sink.example/in"}}),
        ),
        Case::empty(
            "log_streams.listLogStreamDeadLetters",
            "GET",
            format!("{base}/log-streams/{log_stream}/dead-letters"),
        ),
        Case::empty(
            "log_streams.replayLogStreamDeadLetters",
            "POST",
            format!("{base}/log-streams/{log_stream}/dead-letters/replay"),
        ),
        Case::empty(
            "log_streams.deleteLogStream",
            "DELETE",
            format!("{base}/log-streams/lgs_absent"),
        ),
        Case::empty(
            "webhook_endpoints.listWebhookEndpoints",
            "GET",
            format!("{base}/webhook-endpoints"),
        ),
        Case::empty(
            "webhook_endpoints.listWebhookDeliveryAttempts",
            "GET",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/attempts"),
        ),
        Case::empty(
            "webhook_endpoints.listWebhookDeadLetters",
            "GET",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/dead-letters"),
        ),
        Case::json(
            "webhook_endpoints.createWebhookEndpoint",
            "POST",
            format!("{base}/webhook-endpoints"),
            &serde_json::json!({ "url": "https://example.test/hook" }),
        ),
        Case::empty(
            "webhook_endpoints.rotateWebhookEndpointSecret",
            "POST",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/rotate-secret"),
        ),
        Case::json(
            "webhook_endpoints.replayWebhookDeadLetters",
            "POST",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/replay"),
            &serde_json::json!({}),
        ),
        Case::json(
            "webhook_endpoints.setWebhookEventTypes",
            "PUT",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/event-types"),
            &serde_json::json!({ "event_types": ["user.created"] }),
        ),
        Case::empty(
            "webhook_endpoints.pauseWebhookEndpoint",
            "POST",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/pause"),
        ),
        Case::empty(
            "webhook_endpoints.resumeWebhookEndpoint",
            "POST",
            format!("{base}/webhook-endpoints/{webhook_endpoint}/resume"),
        ),
        Case::empty(
            "webhook_endpoints.deleteWebhookEndpoint",
            "DELETE",
            format!("{base}/webhook-endpoints/{webhook_endpoint}"),
        ),
        // ---- per-scope step-up policy (issue #262) ----
        Case::empty(
            "step_up_policies.listStepUpPolicies",
            "GET",
            format!("{base}/step-up-policies"),
        ),
        Case::json(
            "step_up_policies.setStepUpPolicy",
            "POST",
            format!("{base}/step-up-policies"),
            &serde_json::json!({ "scope_token": "payments:write", "min_acr": "aal2" }),
        ),
        Case::empty(
            "step_up_policies.removeStepUpPolicy",
            "DELETE",
            format!("{base}/step-up-policies/payments:write"),
        ),
        // ---- clients and their per-client configuration ----
        Case::empty(
            "dcr.getDcrClient",
            "GET",
            format!("{base}/clients/{client}"),
        ),
        Case::empty(
            "client_scopes.getClientAllowedScopes",
            "GET",
            format!("{base}/clients/{client}/allowed-scopes"),
        ),
        Case::json(
            "client_scopes.setClientAllowedScopes",
            "PUT",
            format!("{base}/clients/{client}/allowed-scopes"),
            &serde_json::json!({ "allowed_scopes": ["openid"] }),
        ),
        Case::json(
            "postures.setClientParRequirement",
            "PUT",
            format!("{base}/clients/{client}/par-requirement"),
            &serde_json::json!({ "required": true }),
        ),
        Case::json(
            "postures.setAutoLinkPosture",
            "PUT",
            format!("{base}/auto-link-posture"),
            &serde_json::json!({ "posture": "off" }),
        ),
        Case::json(
            "signing_algorithm.setClientSigningAlgorithm",
            "PUT",
            format!("{base}/clients/{client}/signing-algorithm"),
            &serde_json::json!({ "algorithm": "EdDSA" }),
        ),
        Case::empty(
            "dcr.verifyDcrClient",
            "POST",
            format!("{base}/clients/{client}/verify"),
        ),
        Case::json(
            "client_admin_grants.setClientAdminConsent",
            "PUT",
            format!("{base}/applications/{client}/admin-consent"),
            &serde_json::json!({ "scope": "openid profile" }),
        ),
        Case::empty(
            "client_admin_grants.getClientAdminConsent",
            "GET",
            format!("{base}/applications/{client}/admin-consent"),
        ),
        Case::empty(
            "client_admin_grants.deleteClientAdminConsent",
            "DELETE",
            format!("{base}/applications/{client}/admin-consent"),
        ),
        Case::json(
            "signup_forms.setSignupForm",
            "PUT",
            format!("{base}/applications/{client}/signup-form"),
            &serde_json::json!({ "fields": [] }),
        ),
        // Declarative claim mappings (issue #113): the same per-client shape as the signup
        // form beside it. An empty rule list, because what these sweeps ask is whether the
        // ENVIRONMENT is checked, and a body that could be refused on its own contents would
        // answer a different question.
        Case::json(
            "claims_mappings.setClaimsMapping",
            "PUT",
            format!("{base}/applications/{client}/claims-mapping"),
            &serde_json::json!({ "rules": [] }),
        ),
        // WASM token hooks (issue #114), the same per-client shape.
        //
        // The body is a REAL component preamble. It is no longer load-bearing for the DELETE --
        // `Fixture::seed` writes a hook into both environments, for the reason the claim
        // mapping's seed gives -- but a body the deploy refuses would make this case measure
        // the component check rather than the environment fence, which is not what the sweep
        // asks. An earlier version of this comment claimed the seed's job as its own.
        //
        // `payload_version` rides in the query because the deploy takes one. It no longer has
        // to: the parameter is `Option`al precisely so an absent one is refused behind the
        // gates rather than by the extractor. Kept because a case should send a well-formed
        // request, and `a_bad_payload_version_is_this_apis_refusal` covers the other side.
        Case {
            label: "token_hooks.deployTokenHook",
            method: "PUT",
            path: format!("{base}/applications/{client}/token-hook?payload_version=1"),
            body: Some(COMPONENT_UPLOAD.to_owned()),
            content_type: "application/wasm",
            token: OPERATOR_TOKEN,
        },
        // Environment VARIABLE management (issue #235). All four operations are environment
        // scoped and take no parent beyond the environment, so a soft-deleted environment must
        // refuse the two writes and the two reads must read exactly like an absent one.
        Case::json(
            "variables.setVariable",
            "PUT",
            format!("{base}/variables/LIVE_SURFACE_PROBE"),
            &serde_json::json!({ "value": "x" }),
        ),
        Case::empty(
            "variables.getVariable",
            "GET",
            format!("{base}/variables/LIVE_SURFACE_PROBE"),
        ),
        Case::empty(
            "variables.deleteVariable",
            "DELETE",
            format!("{base}/variables/LIVE_SURFACE_PROBE"),
        ),
        Case::empty("variables.listVariables", "GET", format!("{base}/variables")),
        // Environment SECRET management (issue #235), the same four shapes. These handlers
        // run against the DATA-plane store, which this harness installs no registry for, so
        // they answer the fail-closed 422 rather than reaching the table. That is exactly
        // what these sweeps are asserting about: not a server error, and a soft-deleted
        // environment still refuses the writes.
        Case::json(
            "secrets.setSecret",
            "PUT",
            format!("{base}/secrets/LIVE_SURFACE_PROBE"),
            &serde_json::json!({ "value": "x" }),
        ),
        Case::empty(
            "secrets.getSecret",
            "GET",
            format!("{base}/secrets/LIVE_SURFACE_PROBE"),
        ),
        Case::empty(
            "secrets.deleteSecret",
            "DELETE",
            format!("{base}/secrets/LIVE_SURFACE_PROBE"),
        ),
        Case::empty("secrets.listSecrets", "GET", format!("{base}/secrets")),
        Case::empty(
            "signup_forms.getSignupForm",
            "GET",
            format!("{base}/applications/{client}/signup-form"),
        ),
        Case::empty(
            "signup_forms.deleteSignupForm",
            "DELETE",
            format!("{base}/applications/{client}/signup-form"),
        ),
        Case::empty(
            "claims_mappings.getClaimsMapping",
            "GET",
            format!("{base}/applications/{client}/claims-mapping"),
        ),
        Case::empty(
            "claims_mappings.deleteClaimsMapping",
            "DELETE",
            format!("{base}/applications/{client}/claims-mapping"),
        ),
        Case::empty(
            "token_hooks.getTokenHook",
            "GET",
            format!("{base}/applications/{client}/token-hook"),
        ),
        // Hook VERSIONS (issue #114 criterion 5). The list is a read and answers an empty
        // array for a client with no history, which is a complete answer rather than a
        // not-found -- so unlike `getTokenHook` it needs no seeded row to be comparable.
        Case::empty(
            "token_hooks.listTokenHookVersions",
            "GET",
            format!("{base}/applications/{client}/token-hook/versions"),
        ),
        // The rollback names version 1, which the seeded hook in `Fixture::seed` created.
        Case::json(
            "token_hooks.rollbackTokenHook",
            "POST",
            format!("{base}/applications/{client}/token-hook/rollback"),
            &serde_json::json!({ "version": 1 }),
        ),
        // The DRAFT RUN (issue #114 criterion 5). A POST that writes nothing, which is why it
        // is here twice over: the operation sweep needs it like any other, and the
        // soft-deleted-environment sweep classifies by METHOD, so a POST that skipped
        // `require_live_environment` would be a write-shaped door into a decommissioned
        // environment even though it stores nothing. Running a hook there is exactly what a
        // fence exists to stop.
        //
        // No `version`, so it runs whatever is deployed: the sweeps care about the door's
        // gates, and pinning a version here would make this case fail when the fixture's
        // history changes for unrelated reasons.
        Case::json(
            "token_hooks.testTokenHook",
            "POST",
            format!("{base}/applications/{client}/token-hook/test"),
            &serde_json::json!({ "grant_type": "authorization_code" }),
        ),
        Case::empty(
            "token_hooks.deleteTokenHook",
            "DELETE",
            format!("{base}/applications/{client}/token-hook"),
        ),
        // ---- brands (issue #475) ----
        // A slug of its OWN, so the set/get/delete lifecycle below cannot disturb the seeded
        // `{brand_slug}` brand the asset cases that follow address.
        Case::json(
            "brands.setBrand",
            "PUT",
            format!("{base}/brands/sweep"),
            &serde_json::json!({ "product_name": "Sweep" }),
        ),
        Case::empty("brands.listBrands", "GET", format!("{base}/brands")),
        // The READ addresses the SEEDED brand, not `sweep`: the soft-deleted-environment sweep
        // requires every read to answer its LIVE answer there, and `sweep` exists only after
        // the write above, which that sweep refuses.
        Case::empty(
            "brands.getBrand",
            "GET",
            format!("{base}/brands/{brand_slug}"),
        ),
        Case::empty(
            "brands.deleteBrand",
            "DELETE",
            format!("{base}/brands/sweep"),
        ),
        // ---- brand assets ----
        Case::raster(
            "brand_assets.setBrandFavicon",
            format!("{base}/brands/{brand_slug}/favicon"),
        ),
        Case::empty(
            "brand_assets.deleteBrandFavicon",
            "DELETE",
            format!("{base}/brands/{brand_slug}/favicon"),
        ),
        Case::raster(
            "brand_assets.setBrandLogo",
            format!("{base}/brands/{brand_slug}/logo"),
        ),
        Case::empty(
            "brand_assets.deleteBrandLogo",
            "DELETE",
            format!("{base}/brands/{brand_slug}/logo"),
        ),
        // ---- configuration snapshot and promotion ----
        Case::empty(
            "config.exportConfigSnapshot",
            "GET",
            format!("{base}/config/snapshot"),
        ),
        Case {
            label: "promotion.planConfigPromotion",
            method: "POST",
            path: format!("{base}/config/promotion/plan"),
            body: Some(snapshot.clone()),
            content_type: "application/json",
            token: OPERATOR_TOKEN,
        },
        Case::json(
            "promotion.applyConfigPromotion",
            "POST",
            format!("{base}/config/promotion/apply"),
            &serde_json::json!({
                "source": serde_json::from_str::<serde_json::Value>(snapshot).expect("the exported snapshot is json"),
                "base_revision": base_revision
            }),
        ),
        // ---- connectors ----
        Case::empty(
            "connectors.listConnectors",
            "GET",
            format!("{base}/connectors"),
        ),
        Case::json(
            "connectors.createConnector",
            "POST",
            format!("{base}/connectors"),
            &serde_json::json!({
                "connector_id": "sweep-connector-2",
                "display_name": "Sweep 2",
                "protocol": "oidc",
                "endpoints": { "issuer": "https://idp2.example" },
                "scopes": ["openid"],
                "client_id": "abc",
                "client_secret": "shhh"
            }),
        ),
        Case::empty(
            "connectors.getConnector",
            "GET",
            format!("{base}/connectors/{connector}"),
        ),
        Case::empty(
            "connectors.getConnectorCapabilities",
            "GET",
            format!("{base}/connectors/{connector}/capabilities"),
        ),
        Case::empty(
            "connector_health.getConnectorHealth",
            "GET",
            format!("{base}/connectors/{connector}/health"),
        ),
        Case::json(
            "connectors.updateConnector",
            "PUT",
            format!("{base}/connectors/{connector}"),
            &serde_json::json!({
                "connector_id": "sweep-connector",
                "display_name": "Sweep renamed",
                "protocol": "oidc",
                "endpoints": { "issuer": "https://idp.example" },
                "scopes": ["openid"],
                "client_id": "abc",
                "client_secret": "shhh"
            }),
        ),
        Case::empty(
            "connectors.deleteConnector",
            "DELETE",
            format!("{base}/connectors/{connector}"),
        ),
        // ---- dynamic client registration policy ----
        Case::json(
            "dcr.createDcrInitialAccessToken",
            "POST",
            format!("{base}/dcr/initial-access-tokens"),
            &serde_json::json!({ "expires_in_secs": 3600 }),
        ),
        Case::empty("dcr.listDcrPolicies", "GET", format!("{base}/dcr/policies")),
        Case::json(
            "dcr.createDcrPolicy",
            "POST",
            format!("{base}/dcr/policies"),
            &serde_json::json!({ "name": "sweep-2", "primitives": [] }),
        ),
        // ---- diagnostics ----
        Case::empty(
            "diagnostics.getClientAuthDiagnostics",
            "GET",
            format!("{base}/diagnostics/client-auth"),
        ),
        Case::json(
            "diagnostics.postFlowDryRun",
            "POST",
            format!("{base}/diagnostics/flow/dry-run"),
            &serde_json::json!({ "journey": "login", "achieved_acr": "pwd" }),
        ),
        Case::empty(
            "diagnostics.getFlowObservation",
            "GET",
            format!("{base}/diagnostics/flow/{observed_flow}"),
        ),
        Case::empty(
            "diagnostics.getPolicyDecisionTraces",
            "GET",
            format!("{base}/diagnostics/policy-traces"),
        ),
        Case::empty(
            "diagnostics.getDiagnosticsWarnings",
            "GET",
            format!("{base}/diagnostics/warnings"),
        ),
        // ---- identity export ----
        Case::empty("export.exportIdentities", "GET", format!("{base}/export")),
        // ---- invitations ----
        Case::empty(
            "invitations.listInvitations",
            "GET",
            format!("{base}/invitations"),
        ),
        Case::json(
            "invitations.createInvitation",
            "POST",
            format!("{base}/invitations"),
            &serde_json::json!({ "identifier": "invited2@example.test" }),
        ),
        Case::empty(
            "invitations.getInvitation",
            "GET",
            format!("{base}/invitations/{invitation}"),
        ),
        Case::empty(
            "invitations.resendInvitation",
            "POST",
            format!("{base}/invitations/{invitation}/resend"),
        ),
        Case::empty(
            "invitations.revokeInvitation",
            "POST",
            format!("{base}/invitations/{invitation}/revoke"),
        ),
        // ---- journeys and pinned flow versions ----
        Case::empty(
            "flow_versions.listFlowVersions",
            "GET",
            format!("{base}/journeys/login/versions"),
        ),
        Case::json(
            "flow_versions.createFlowVersion",
            "POST",
            format!("{base}/journeys/login/versions"),
            &serde_json::json!({
                "artifact": {
                    "schema_version": "ironauth.journey/v1",
                    "id": "login",
                    "engine_version": 1,
                    "entry": "primary",
                    "steps": [
                        {"id": "primary", "kind": "identifier_password", "node_group": "password"},
                        {"id": "done", "kind": "terminal"}
                    ],
                    "transitions": [{"from": "primary", "to": "done"}]
                }
            }),
        ),
        Case::empty(
            "flow_versions.getFlowVersion",
            "GET",
            format!("{base}/journeys/login/versions/{flow_version}"),
        ),
        Case::empty(
            "flow_versions.pinFlowVersion",
            "POST",
            format!("{base}/journeys/login/versions/{flow_version}/pin"),
        ),
        // ---- identity trait schemas (issue #53) ----
        Case::empty(
            "trait_schemas.listTraitSchemaVersions",
            "GET",
            format!("{base}/trait-schemas"),
        ),
        Case::json(
            "trait_schemas.createTraitSchemaVersion",
            "POST",
            format!("{base}/trait-schemas"),
            &serde_json::json!({ "schema": {"type": "object", "properties": {}} }),
        ),
        Case::json(
            "trait_schemas.createTraitMigrationJob",
            "POST",
            format!("{base}/trait-schemas/migrations"),
            &serde_json::json!({ "kind": "dry_run", "from_version": 1, "to_version": 1 }),
        ),
        Case::empty(
            "trait_schemas.getTraitMigrationJob",
            "GET",
            format!("{base}/trait-schemas/migrations/tmj_absent"),
        ),
        Case::empty(
            "trait_schemas.getActiveTraitSchema",
            "GET",
            format!("{base}/trait-schemas/active"),
        ),
        Case::empty(
            "trait_schemas.getTraitSchemaVersion",
            "GET",
            format!("{base}/trait-schemas/{trait_schema_version}"),
        ),
        Case::empty(
            "trait_schemas.activateTraitSchemaVersion",
            "POST",
            format!("{base}/trait-schemas/{trait_schema_version}/activate"),
        ),
        // ---- management keys ----
        Case::empty("keys.listManagementKeys", "GET", format!("{base}/keys")),
        Case::json(
            "keys.createManagementKey",
            "POST",
            format!("{base}/keys"),
            &serde_json::json!({ "display_name": "Sweep 2" }),
        ),
        Case::empty("keys.getManagementKey", "GET", format!("{base}/keys/{key}")),
        Case::empty(
            "keys.deleteManagementKey",
            "DELETE",
            format!("{base}/keys/{key}"),
        ),
        // ---- locales ----
        Case::json(
            "locales.setLocale",
            "PUT",
            format!("{base}/locales/en"),
            &serde_json::json!({ "entries": { "1010001": "Sign in" } }),
        ),
        Case::empty("locales.getLocale", "GET", format!("{base}/locales/en")),
        Case::empty(
            "locales.deleteLocale",
            "DELETE",
            format!("{base}/locales/en"),
        ),
        // ---- the streaming bulk-import job (issue #55) ----
        Case::ndjson(
            "imports.createIdentityImport",
            format!("{base}/imports?source_total=1"),
            "{\"identifier\":\"live-sweep-import@x.test\"}\n",
        ),
        Case::ndjson(
            "imports.resumeIdentityImport",
            format!("{base}/imports/{migration_run}"),
            "{\"identifier\":\"live-sweep-resume@x.test\"}\n",
        ),
        // ---- lazy migration ----
        Case::empty(
            "migration_runs.listMigrationRuns",
            "GET",
            format!("{base}/migration-runs"),
        ),
        Case::empty(
            "migration_runs.getMigrationRun",
            "GET",
            format!("{base}/migration-runs/{migration_run}"),
        ),
        Case::empty(
            "migration_runs.listMigrationRunViolations",
            "GET",
            format!("{base}/migration-runs/{migration_run}/violations"),
        ),
        // Driven LAST of the migration-run cases, because it is terminal: the seeded run
        // is abandoned here and every case above has already used it.
        Case::json(
            "migration_runs.abandonMigrationRun",
            "POST",
            format!("{base}/migration-runs/{migration_run}/abandon"),
            &serde_json::json!({ "reason": "the live-surface sweep abandons its seeded run" }),
        ),
        Case::empty(
            "migration_status.getMigrationProgress",
            "GET",
            format!("{base}/migration/progress"),
        ),
        Case::json(
            "migration.verifyMigrationCredential",
            "POST",
            format!("{base}/migration/verify-credential"),
            &serde_json::json!({ "identifier": "sweep@example.test", "password": "hunter2hunter2" }),
        )
        .with_bearer(OUTBOUND_TOKEN),
        Case::empty(
            "migration.getOutboundVerification",
            "GET",
            format!("{base}/migration/outbound-verification"),
        ),
        Case::json(
            "migration.setOutboundVerification",
            "PUT",
            format!("{base}/migration/outbound-verification"),
            &serde_json::json!({ "token": "a-rotated-outbound-token-of-32-plus-bytes" }),
        ),
        Case::empty(
            "migration.deleteOutboundVerification",
            "DELETE",
            format!("{base}/migration/outbound-verification"),
        ),
        // ---- organizations ----
        Case::empty(
            "organizations.listOrganizations",
            "GET",
            format!("{base}/organizations"),
        ),
        Case::json(
            "organizations.createOrganization",
            "POST",
            format!("{base}/organizations"),
            &serde_json::json!({ "display_name": "Sweep 2" }),
        ),
        Case::empty("organizations.getOrganization", "GET", org_base.clone()),
        Case::json(
            "org_roles.setOrgDefaultRole",
            "PUT",
            format!("{org_base}/default-role"),
            &role_ref.clone(),
        ),
        Case::empty(
            "org_roles.clearOrgDefaultRole",
            "DELETE",
            format!("{org_base}/default-role"),
        ),
        Case::empty(
            "organizations.disableOrganization",
            "POST",
            format!("{org_base}/disable"),
        ),
        Case::empty(
            "organizations.enableOrganization",
            "POST",
            format!("{org_base}/enable"),
        ),
        // ---- organization groups ----
        Case::empty(
            "org_groups.listOrgGroups",
            "GET",
            format!("{org_base}/groups"),
        ),
        Case::json(
            "org_groups.createOrgGroup",
            "POST",
            format!("{org_base}/groups"),
            &serde_json::json!({ "slug": "sweep-2", "display_name": "Sweep 2" }),
        ),
        Case::empty(
            "org_groups.getOrgGroup",
            "GET",
            format!("{org_base}/groups/{group}"),
        ),
        Case::json(
            "org_groups.updateOrgGroup",
            "PATCH",
            format!("{org_base}/groups/{group}"),
            &serde_json::json!({ "display_name": "Sweep renamed" }),
        ),
        Case::json(
            "org_groups.setOrgGroupParent",
            "PUT",
            format!("{org_base}/groups/{group}/parent"),
            &serde_json::json!({ "parent_id": null }),
        ),
        Case::empty(
            "org_group_members.listOrgGroupMembers",
            "GET",
            format!("{org_base}/groups/{group}/members"),
        ),
        Case::json(
            "org_group_members.addOrgGroupMember",
            "POST",
            format!("{org_base}/groups/{group}/members"),
            &serde_json::json!({ "membership_id": membership }),
        ),
        Case::empty(
            "org_group_members.removeOrgGroupMember",
            "DELETE",
            format!("{org_base}/groups/{group}/members/{membership}"),
        ),
        Case::empty(
            "org_role_assignments.listOrgGroupRoles",
            "GET",
            format!("{org_base}/groups/{group}/roles"),
        ),
        Case::json(
            "org_role_assignments.assignOrgGroupRole",
            "POST",
            format!("{org_base}/groups/{group}/roles"),
            &role_ref.clone(),
        ),
        Case::empty(
            "org_role_assignments.unassignOrgGroupRole",
            "DELETE",
            format!("{org_base}/groups/{group}/roles/{role}"),
        ),
        Case::empty(
            "org_groups.deleteOrgGroup",
            "DELETE",
            format!("{org_base}/groups/{group}"),
        ),
        // ---- organization memberships ----
        Case::empty(
            "memberships.listMemberships",
            "GET",
            format!("{org_base}/memberships"),
        ),
        Case::json(
            "memberships.createMembership",
            "POST",
            format!("{org_base}/memberships"),
            &serde_json::json!({ "user_id": unenrolled_user }),
        ),
        Case::empty(
            "org_effective_roles.getOrgMembershipEffectiveRoles",
            "GET",
            format!("{org_base}/memberships/{membership}/effective-roles"),
        ),
        Case::empty(
            "org_role_assignments.listOrgMembershipRoles",
            "GET",
            format!("{org_base}/memberships/{membership}/roles"),
        ),
        Case::json(
            "org_role_assignments.assignOrgMembershipRole",
            "POST",
            format!("{org_base}/memberships/{membership}/roles"),
            &role_ref,
        ),
        Case::empty(
            "org_role_assignments.unassignOrgMembershipRole",
            "DELETE",
            format!("{org_base}/memberships/{membership}/roles/{role}"),
        ),
        // Project grants (issue #102). The create names an EMPTY role subset, which is
        // valid and means this organization's delegated administrators may assign
        // nothing. It also uses a DIFFERENT application from the seeded grant's, because
        // migration 0120 permits at most one live grant per (client, organization) pair.
        // Enterprise inbound routing (issue #96).
        Case::empty(
            "routing_rules.listRoutingRules",
            "GET",
            format!("{base}/routing-rules"),
        ),
        Case::empty(
            "routing_rules.verifyRoutingRuleDomain",
            "POST",
            format!("{base}/routing-rules/{routing_rule}/verify-domain"),
        ),
        Case::json(
            "routing_rules.createRoutingRule",
            "POST",
            format!("{base}/routing-rules"),
            &serde_json::json!({
                "kind": "domain",
                "value": "sweep.example",
                "org_connection_id": org_connection,
            }),
        ),
        Case::json(
            "api_keys.createOrganizationApiKey",
            "POST",
            format!("{org_base}/api-keys"),
            &serde_json::json!({ "display_name": "sweep key" }),
        ),
        Case::empty(
            "api_keys.listOrganizationApiKeys",
            "GET",
            format!("{org_base}/api-keys"),
        ),
        // A handle that does not exist. This sweep asserts the ENVIRONMENT fence, not the
        // key lookup, so a 404 for an unknown key on a live environment and the uniform
        // refusal on a deleted one are exactly the pair it wants to compare.
        Case::empty(
            "api_keys.rotateOrganizationApiKey",
            "POST",
            format!("{org_base}/api-keys/{api_key}/rotate"),
        ),
        // Revoke comes AFTER rotate: rotate already revoked this handle, so revoking it
        // again is the already-revoked path, which is still a 404 at a live environment.
        // Both orderings drive the fence; this one also exercises the interaction.
        Case::empty(
            "api_keys.revokeOrganizationApiKey",
            "DELETE",
            format!("{org_base}/api-keys/{api_key}"),
        ),
        // The service-account surface, same four shapes. Not nested under an organization:
        // `service_accounts` has no organization column, so the path addresses the
        // environment directly.
        Case::json(
            "service_account_keys.createServiceAccountApiKey",
            "POST",
            sa_base.clone(),
            &serde_json::json!({ "display_name": "sweep machine key" }),
        ),
        Case::empty(
            "service_account_keys.listServiceAccountApiKeys",
            "GET",
            sa_base.clone(),
        ),
        // The client's principal, which is how the console reaches the keys above.
        Case::empty(
            "service_account_keys.getClientServiceAccount",
            "GET",
            format!("{base}/clients/{client}/service-account"),
        ),
        Case::empty(
            "service_account_keys.rotateServiceAccountApiKey",
            "POST",
            format!("{sa_base}/{sa_api_key}/rotate"),
        ),
        // After rotate, as on the organization surface: the handle is already revoked, which
        // is a 404 at a live environment, and the pair with the deleted-environment refusal
        // is what the sweep compares.
        Case::empty(
            "service_account_keys.revokeServiceAccountApiKey",
            "DELETE",
            format!("{sa_base}/{sa_api_key}"),
        ),
        // Personal access tokens, the third owner kind, same four shapes.
        Case::json(
            "personal_access_tokens.createUserPersonalAccessToken",
            "POST",
            pat_base.clone(),
            &serde_json::json!({ "display_name": "sweep pat" }),
        ),
        Case::empty(
            "personal_access_tokens.listUserPersonalAccessTokens",
            "GET",
            pat_base.clone(),
        ),
        Case::empty(
            "personal_access_tokens.rotateUserPersonalAccessToken",
            "POST",
            format!("{pat_base}/{pat}/rotate"),
        ),
        Case::empty(
            "personal_access_tokens.revokeUserPersonalAccessToken",
            "DELETE",
            format!("{pat_base}/{pat}"),
        ),
        // Authorizing an impersonation (issue #101). An environment-scoped write, so the
        // soft-deleted sweep must refuse it too.
        Case::json(
            "impersonation.authorizeUserImpersonation",
            "POST",
            format!("{base}/users/{user}/impersonation"),
            &serde_json::json!({
                "reason_code": "support_ticket",
                "reason_text": "sweep impersonation",
            }),
        ),
        Case::empty(
            "project_grants.listProjectGrants",
            "GET",
            format!("{org_base}/project-grants"),
        ),
        Case::json(
            "project_grants.createProjectGrant",
            "POST",
            format!("{org_base}/project-grants"),
            &serde_json::json!({ "client_id": client, "role_ids": [] }),
        ),
        Case::empty(
            "project_grants.withdrawProjectGrant",
            "DELETE",
            format!("{org_base}/project-grants/{project_grant}"),
        ),
        Case::empty(
            "memberships.deleteMembership",
            "DELETE",
            format!("{org_base}/memberships/{membership}"),
        ),
        // ---- organization roles and their permissions ----
        Case::empty("org_roles.listOrgRoles", "GET", format!("{org_base}/roles")),
        Case::json(
            "org_roles.createOrgRole",
            "POST",
            format!("{org_base}/roles"),
            &serde_json::json!({ "slug": "sweep-2", "display_name": "Sweep 2" }),
        ),
        Case::empty(
            "org_roles.getOrgRole",
            "GET",
            format!("{org_base}/roles/{role}"),
        ),
        Case::json(
            "org_roles.updateOrgRole",
            "PATCH",
            format!("{org_base}/roles/{role}"),
            &serde_json::json!({ "display_name": "Sweep renamed" }),
        ),
        Case::empty(
            "org_role_permissions.listOrgRolePermissions",
            "GET",
            format!("{org_base}/roles/{role}/permissions"),
        ),
        // The AuthZEN PDP (issue #100). The two evaluation bodies name the REAL organization
        // and a REAL user, so they reach `effective_permissions` rather than stopping at the
        // handler's own 400 for a missing `context.organization_id`, which would pass this
        // sweep while saying nothing about the grant the resolution needs.
        Case::empty(
            "authzen.getAuthzenConfiguration",
            "GET",
            format!("{base}/.well-known/authzen-configuration"),
        ),
        Case::json(
            "authzen.authzenEvaluation",
            "POST",
            format!("{base}/access/v1/evaluation"),
            &serde_json::json!({
                "subject": { "type": "user", "id": user },
                "resource": { "type": "billing.invoice" },
                "action": { "name": "read" },
                "context": { "organization_id": organization },
            }),
        ),
        Case::json(
            "authzen.authzenEvaluations",
            "POST",
            format!("{base}/access/v1/evaluations"),
            &serde_json::json!({
                "subject": { "type": "user", "id": user },
                "resource": { "type": "billing.invoice" },
                "action": { "name": "read" },
                "context": { "organization_id": organization },
                "evaluations": [{}],
            }),
        ),
        Case::json(
            "org_role_permissions.assignOrgRolePermission",
            "POST",
            format!("{org_base}/roles/{role}/permissions"),
            &serde_json::json!({ "permission_id": permission }),
        ),
        Case::empty(
            "org_role_permissions.unassignOrgRolePermission",
            "DELETE",
            format!("{org_base}/roles/{role}/permissions/{permission}"),
        ),
        Case::empty(
            "org_roles.deleteOrgRole",
            "DELETE",
            format!("{org_base}/roles/{role}"),
        ),
        Case::empty("organizations.deleteOrganization", "DELETE", org_base),
        // ---- password hashing probe ----
        Case::json(
            "password_hashing.probePasswordHashing",
            "POST",
            format!("{base}/password-hashing/probe"),
            &serde_json::json!({}),
        ),
        // ---- permissions ----
        Case::empty(
            "permissions.listPermissions",
            "GET",
            format!("{base}/permissions"),
        ),
        Case::json(
            "permissions.createPermission",
            "POST",
            format!("{base}/permissions"),
            &serde_json::json!({ "slug": "sweep.write", "display_name": "Sweep 2" }),
        ),
        Case::empty(
            "permissions.getPermission",
            "GET",
            format!("{base}/permissions/{permission}"),
        ),
        Case::json(
            "permissions.updatePermission",
            "PATCH",
            format!("{base}/permissions/{permission}"),
            &serde_json::json!({ "display_name": "Sweep renamed" }),
        ),
        Case::empty(
            "permissions.deletePermission",
            "DELETE",
            format!("{base}/permissions/{permission}"),
        ),
        // ---- the recovery review queue ----
        Case::empty(
            "recovery_approvals.listRecoveryApprovals",
            "GET",
            format!("{base}/recovery-approvals"),
        ),
        Case::empty(
            "recovery_approvals.rejectRecoveryApproval",
            "POST",
            format!("{base}/recovery-approvals/{recovery_flow_to_reject}/reject"),
        ),
        Case::empty(
            "recovery_approvals.approveRecoveryApproval",
            "POST",
            format!("{base}/recovery-approvals/{recovery_flow}/approve"),
        ),
        // ---- refresh families ----
        Case::empty(
            "sessions.listRefreshFamilies",
            "GET",
            format!("{base}/refresh-families"),
        ),
        Case::empty(
            "sessions.getRefreshFamily",
            "GET",
            format!("{base}/refresh-families/{family}"),
        ),
        // ---- resource servers ----
        Case::empty(
            "resource_servers.listResourceServers",
            "GET",
            format!("{base}/resource-servers"),
        ),
        Case::empty(
            "resource_servers.getResourceServer",
            "GET",
            format!("{base}/resource-servers/{resource_server}"),
        ),
        Case::json(
            "resource_servers.updateResourceServerPermissionClaims",
            "PATCH",
            format!("{base}/resource-servers/{resource_server}"),
            &serde_json::json!({ "permission_claims_enabled": true }),
        ),
        // ---- the ordered event feed and usage export (issue #107) ----
        // Both are environment-scoped READS folded from the outbox, so the sweep drives
        // them exactly as it drives any other list: they must answer for a live scope and
        // refuse a soft-deleted one like everything else here.
        Case::empty("event_feed.readEventFeed", "GET", format!("{base}/events")),
        Case::empty("usage.exportUsage", "GET", format!("{base}/usage")),
        // PUBLISHING is the write half, and it is here for the reason the read half is not
        // enough: it appends to the feed every webhook subscriber receives, so a
        // soft-deleted environment that could still publish would keep sending billing
        // records after the operator believed it gone.
        Case::empty(
            "usage.publishUsage",
            "POST",
            format!("{base}/usage/publish"),
        ),
        // ---- sessions ----
        Case::empty("sessions.listSessions", "GET", format!("{base}/sessions")),
        Case::empty(
            "sessions.getSession",
            "GET",
            format!("{base}/sessions/{session}"),
        ),
        Case::json(
            "sessions.revokeSession",
            "POST",
            format!("{base}/sessions/{session}/revoke"),
            &serde_json::json!({}),
        ),
        Case::json(
            "sessions.bulkRevokeSessions",
            "POST",
            format!("{base}/sessions/revoke"),
            &serde_json::json!({ "session_ids": [session] }),
        ),
        // ---- the signup fraud-review queue ----
        Case::empty(
            "signup_quarantine.listSignupQuarantines",
            "GET",
            format!("{base}/signup-quarantine"),
        ),
        Case::json(
            "signup_quarantine.extendSignupQuarantine",
            "POST",
            format!("{base}/signup-quarantine/{quarantined_user}/extend"),
            &serde_json::json!({ "extend_secs": 3600 }),
        ),
        Case::empty(
            "signup_quarantine.rejectSignupQuarantine",
            "POST",
            format!("{base}/signup-quarantine/{quarantined_user}/reject"),
        ),
        Case::empty(
            "signup_quarantine.approveSignupQuarantine",
            "POST",
            format!("{base}/signup-quarantine/{second_quarantined_user}/approve"),
        ),
        // ---- users ----
        Case::empty("users.listUsers", "GET", format!("{base}/users")),
        Case::json(
            "users.createUser",
            "POST",
            format!("{base}/users"),
            &serde_json::json!({ "identifier": "sweep2@example.test" }),
        ),
        Case::empty("users.getUser", "GET", format!("{base}/users/{user}")),
        Case::empty(
            "users.getUserTraits",
            "GET",
            format!("{base}/users/{user}/traits"),
        ),
        // The user's typed login identifiers (issue #54, epic #514). The READ answers as
        // if live in a soft-deleted environment, like every other user-scoped read, and
        // the POST is a write, so it must refuse one.
        // The environment-level uniqueness mode routes (epic #514). The read evaluates a
        // candidate mode and answers as if live in a soft-deleted environment, like every
        // other read; the apply is a write and must refuse one.
        // Guarded SMS OTP configuration (issue #70). The two reads answer as if live in a
        // soft-deleted environment like every other read; the three writes must refuse one.
        // The risk posture reads (issue #79). Both are reads, so a soft-deleted environment
        // answers as if live, like every other read on this surface.
        Case::empty(
            "diagnostics.getUserRiskPosture",
            "GET",
            format!("{base}/diagnostics/risk/users/{user}"),
        ),
        Case::empty(
            "diagnostics.getRiskDecision",
            "GET",
            format!("{base}/diagnostics/risk/decisions/rsk_livesurfaceprobe00000000"),
        ),
        Case::empty(
            "sms_otp.getSmsOtpConfig",
            "GET",
            format!("{base}/sms-otp/config"),
        ),
        Case::json(
            "sms_otp.setSmsOtpConfig",
            "PUT",
            format!("{base}/sms-otp/config"),
            &serde_json::json!({ "enabled": true }),
        ),
        Case::empty(
            "sms_otp.listSmsAllowlist",
            "GET",
            format!("{base}/sms-otp/allowlist"),
        ),
        Case::empty(
            "sms_otp.allowSmsCountry",
            "PUT",
            format!("{base}/sms-otp/allowlist/44"),
        ),
        Case::empty(
            "sms_otp.denySmsCountry",
            "DELETE",
            format!("{base}/sms-otp/allowlist/44"),
        ),
        Case::empty(
            "identifiers.getIdentifierUniqueness",
            "GET",
            format!("{base}/identifier-uniqueness"),
        ),
        Case::empty(
            "identifiers.applyIdentifierUniqueness",
            "POST",
            format!("{base}/identifier-uniqueness/apply"),
        ),
        Case::empty(
            "users.listUserIdentifiers",
            "GET",
            format!("{base}/users/{user}/identifiers"),
        ),
        Case::json(
            "users.addUserIdentifier",
            "POST",
            format!("{base}/users/{user}/identifiers"),
            &serde_json::json!({ "type": "email", "value": "live-surface@example.test" }),
        ),
        Case::empty(
            "users.removeUserIdentifier",
            "DELETE",
            format!("{base}/users/{user}/identifiers/{user_identifier}"),
        ),
        Case::json(
            "users.updateUser",
            "PATCH",
            format!("{base}/users/{user}"),
            &serde_json::json!({ "claims": {} }),
        ),
        Case::empty(
            "consents.listUserConsents",
            "GET",
            format!("{base}/users/{user}/consents"),
        ),
        Case::empty(
            "consents.revokeUserConsent",
            "POST",
            format!("{base}/users/{user}/consents/{client}/revoke"),
        ),
        Case::json(
            "users.linkUserExternalId",
            "PUT",
            format!("{base}/users/{user}/external-id"),
            &serde_json::json!({ "external_id": "ext-1" }),
        ),
        Case::empty(
            "users.unlinkUserExternalId",
            "DELETE",
            format!("{base}/users/{user}/external-id"),
        ),
        Case::json(
            "users.revokeUserSessions",
            "POST",
            format!("{base}/users/{user}/sessions/revoke"),
            &serde_json::json!({}),
        ),
        Case::json(
            "users.setUserState",
            "POST",
            format!("{base}/users/{user}/state"),
            &serde_json::json!({ "state": "blocked" }),
        ),
        Case::empty("users.deleteUser", "DELETE", format!("{base}/users/{user}")),
        // ---- WebAuthn metadata health ----
        Case::empty(
            "mds3_health.getMds3Health",
            "GET",
            format!("{base}/webauthn/mds3/health"),
        ),
        // ---- the admin sudo elevation ----
        //
        // The ONE route this harness cannot arm alongside the rest: sudo mode gates every
        // environment-scoped mutation on a fresh elevation, so arming it here would turn
        // the whole sweep into a 403 sweep. Driven at the unarmed router this answers the
        // uniform not-found, which is not a server error but is also not a measurement, so
        // `the_sudo_elevation_answers_against_a_live_environment_when_armed` drives it at
        // an armed one.
        Case::empty(
            "sudo.elevateAdminSudo",
            "POST",
            format!("{base}/admin/sudo/elevate"),
        ),
        // ---- the destructive operator-plane lifecycle, on the throwaway tenant ----
        Case::empty(
            "environments.deleteEnvironment",
            "DELETE",
            format!("/v1/tenants/{tenant}/environments/{doomed_environment}"),
        ),
        Case::empty(
            "tenants.suspendTenant",
            "POST",
            format!("/v1/tenants/{doomed_tenant}/suspend"),
        ),
        Case::empty(
            "tenants.resumeTenant",
            "POST",
            format!("/v1/tenants/{doomed_tenant}/resume"),
        ),
        Case::empty(
            "tenants.deleteTenant",
            "DELETE",
            format!("/v1/tenants/{doomed_tenant}"),
        ),
        // Between the delete and the restore, so the tenant is in GRACE when this runs and
        // the purge exercises its retention gate (a 409 under the default window) rather
        // than the bare not-found it would answer on a live tenant. It leaves the tenant in
        // grace, so the restore below still has something to restore.
        Case::empty(
            "tenants.purgeTenant",
            "POST",
            format!("/v1/tenants/{doomed_tenant}/purge"),
        ),
        Case::empty(
            "tenants.restoreTenant",
            "POST",
            format!("/v1/tenants/{doomed_tenant}/restore"),
        ),
    ]
}

/// Drive one case with the bootstrap operator token, carrying an Idempotency-Key on every
/// request (the routes that require one get it; the rest ignore it), returning the
/// HEADERS as well as the status and the body.
///
/// The headers are not decoration for the soft-deleted sweep below: its claim is that
/// every refusal is the SAME refusal, and two responses that agree on the status and the
/// body can still differ in what a client actually receives.
async fn drive_observed(h: &Harness, case: &Case, key: &str) -> (StatusCode, HeaderMap, String) {
    let request = Request::builder()
        .method(case.method)
        .uri(&case.path)
        .header(header::AUTHORIZATION, bearer(case.token))
        .header("idempotency-key", key)
        .header(header::CONTENT_TYPE, case.content_type)
        .body(case.body.clone().map_or_else(Body::empty, Body::from))
        .expect("request builds");
    h.send(request).await
}

/// Drive one case, keeping only the status and the body.
async fn drive(h: &Harness, case: &Case, key: &str) -> (StatusCode, String) {
    let (status, _, body) = drive_observed(h, case, key).await;
    (status, body)
}

#[test]
fn every_documented_operation_is_driven_by_a_case() {
    // The guard on the guard. It needs no database, so it is the cheapest thing in the
    // file and the first thing to fail. Without it the sweep below would report on
    // whatever the case list happened to contain, and a route deleted from the list would
    // leave the suite green while its live answer went unmeasured. That is not a
    // hypothetical: it is exactly how the sibling sweep in `absent_environment.rs` had
    // silently drifted to 73 of 75 writes before the same check was added there.
    //
    // The fixture ids are placeholders here; only the SHAPE of each path is examined.
    let fixture = Fixture {
        tenant: "ten_0".to_owned(),
        environment: "env_0".to_owned(),
        doomed_tenant: "ten_1".to_owned(),
        doomed_environment: "env_1".to_owned(),
        operator: "opr_0".to_owned(),
        client: "cli_0".to_owned(),
        message: "msg_0".to_owned(),
        service_account: "sva_0".to_owned(),
        sa_api_key: "akey_0".to_owned(),
        pat: "akey_1".to_owned(),
        org_connection: "ocn_0".to_owned(),
        routing_rule: "rrl_0".to_owned(),
        project_grant: "pgt_0".to_owned(),
        api_key: "akey_0".to_owned(),
        connector: "con_0".to_owned(),
        log_stream: "lgs_0".to_owned(),
        flow_target: "ftg_0".to_owned(),
        webhook_endpoint: "whe_0".to_owned(),
        external_issuer: "xai_0".to_owned(),
        subject_mapping: "asm_0".to_owned(),
        family: "rfm_0".to_owned(),
        recovery_flow: "rcf_0".to_owned(),
        group: "grp_0".to_owned(),
        invitation: "inv_0".to_owned(),
        key: "mgk_0".to_owned(),
        membership: "mem_0".to_owned(),
        organization: "org_0".to_owned(),
        permission: "prm_0".to_owned(),
        resource_server: "rsv_0".to_owned(),
        role: "rol_0".to_owned(),
        migration_run: "mgr_0".to_owned(),
        session: "ses_0".to_owned(),
        user: "usr_0".to_owned(),
        user_identifier: "uid_0".to_owned(),
        quarantined_user: "usr_1".to_owned(),
        second_quarantined_user: "usr_2".to_owned(),
        unenrolled_user: "usr_3".to_owned(),
        recovery_flow_to_reject: "rcf_1".to_owned(),
        observed_flow: "flw_0".to_owned(),
        brand_slug: "default".to_owned(),
        snapshot: "{}".to_owned(),
        base_revision: "0".to_owned(),
        flow_version: 1,
        trait_schema_version: 1,
    };
    let cases = all_cases(&fixture);
    let documented = documented_operations();

    // 1. Every case addresses exactly ONE documented operation, and its label names that
    //    operation. A case whose path has a typo in a LITERAL segment matches no template
    //    at all and fails here, which is the hole a status-only sweep cannot see: axum
    //    answers an unrouted path with a 404, and a 404 is not a server error.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for case in &cases {
        let mut addressed: Vec<&DocumentedOperation> = documented
            .iter()
            .filter(|op| op.method == case.method && template_matches(&op.template, &case.path))
            .collect();
        // Keep only the MOST SPECIFIC matches, which is the router's own rule: a template
        // whose segment is a literal outranks one whose segment is a parameter. Anything
        // still tied after that is genuinely ambiguous and fails below.
        if let Some(best) = addressed
            .iter()
            .map(|op| parameter_count(&op.template))
            .min()
        {
            addressed.retain(|op| parameter_count(&op.template) == best);
        }
        let named: Vec<&str> = addressed
            .iter()
            .map(|op| op.operation_id.as_str())
            .collect();
        assert_eq!(
            addressed.len(),
            1,
            "{} drives {} {}, which addresses {} documented operations rather than exactly one: {named:?}",
            case.label,
            case.method,
            case.path,
            addressed.len()
        );
        let operation = addressed[0].operation_id.clone();
        assert!(
            case.label.ends_with(&format!(".{operation}")),
            "the case label `{}` must name the operation it actually drives (`{operation}`)",
            case.label
        );
        assert!(
            covered.insert(operation.clone()),
            "{operation} is driven by more than one case"
        );
    }

    // 2. And every documented operation is driven by a case. This is the direction that
    //    makes a NEW route fail the sweep the moment it is documented.
    let published: BTreeSet<String> = documented
        .iter()
        .map(|op| op.operation_id.clone())
        .collect();
    let undriven: Vec<&String> = published.difference(&covered).collect();
    assert!(
        undriven.is_empty(),
        "the committed contract publishes {} operations and this sweep drives {}; add a case \
         for each of these before the sweep can claim to cover the surface: {undriven:?}",
        published.len(),
        covered.len()
    );
}

#[tokio::test]
async fn no_management_operation_answers_a_server_error_against_a_live_environment() {
    // The whole-surface guard. Every case addresses a REAL row in a REAL environment with
    // a real operator credential, which is the only configuration in which a missing
    // control-role grant is observable: the control plane is refused by Postgres before
    // any application logic runs, and the router has nowhere to put that but a 500.
    //
    // The assertion is deliberately weak per route (not a server error) and strong across
    // the surface (every route, no exceptions list). Each route's own file owns its exact
    // answers; what no single file owned before was the property that the surface is
    // reachable AT ALL under the production role split.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let fixture = Fixture::seed(&h).await;

    let mut failures: Vec<String> = Vec::new();
    for (index, case) in all_cases(&fixture).iter().enumerate() {
        let (status, body) = drive(&h, case, &format!("k-live-{index}")).await;
        if status.is_server_error() {
            failures.push(format!(
                "{} {} {} -> {status}: {body}",
                case.label, case.method, case.path
            ));
        }
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{} is not routed at the method this sweep drives: {body}",
            case.label
        );
    }

    assert!(
        failures.is_empty(),
        "{} management operations answer a server error against a LIVE, healthy \
         environment. Each one is a dead surface: no request an operator can make will \
         ever succeed there.\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn the_ban_surface_places_lists_and_lifts_a_ban_end_to_end() {
    // The reported instance, driven for its REAL answers rather than merely for the
    // absence of a 500. A sweep that only forbids server errors would stay green if a
    // handler were changed to swallow the refusal and answer an empty 200, which is a
    // worse outcome than the 500 it replaced: an operator would believe a ban was placed.
    //
    // Every assertion here is about the value the operator sees, and the LIST read is what
    // ties the create to the lift: the ban has to be visible on the management plane
    // between them, opened out of its sealed form, or the round trip proves nothing about
    // what was stored.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let bans = format!("/v1/tenants/{tenant}/environments/{environment}/abuse/bans");

    // An empty environment lists no bans. This is the read that used to be refused
    // outright, so it is asserted before anything is placed.
    let (status, _, body) = h.get(&bans).await;
    assert_eq!(status, StatusCode::OK, "the ban list is readable: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        listed["bans"].as_array().expect("bans array").len(),
        0,
        "a fresh environment holds no bans: {body}"
    );

    // Place one.
    let request = serde_json::json!({
        "subject_kind": "identifier",
        "subject": "Abuser@Example.Test",
        "auth_path": "password",
        "reason": "operator placed"
    })
    .to_string();
    let (status, _, body) = h.post(&bans, "k-create", &request).await;
    assert_eq!(status, StatusCode::CREATED, "the ban is placed: {body}");
    let placed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(
        placed["id"].as_str().expect("id").starts_with("abn_"),
        "the placed ban carries its own id: {body}"
    );
    assert_eq!(
        placed["subject"].as_str().expect("subject"),
        "abuser@example.test",
        "an identifier subject is canonicalized through the login seam: {body}"
    );
    assert_eq!(placed["auth_path"].as_str().expect("auth_path"), "password");
    assert_eq!(
        placed["reason"].as_str().expect("reason"),
        "operator placed"
    );
    assert!(
        placed["expires_at_unix_ms"].is_null(),
        "an omitted expiry is a permanent ban: {body}"
    );

    // The management plane can READ BACK what it wrote, subject opened. This is the
    // assertion the grant question turns on: the control role's SELECT is what makes a
    // placed ban visible to the operator who placed it.
    let (status, _, body) = h.get(&bans).await;
    assert_eq!(status, StatusCode::OK, "the ban list is readable: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let rows = listed["bans"].as_array().expect("bans array");
    assert_eq!(rows.len(), 1, "exactly the ban just placed: {body}");
    assert_eq!(
        rows[0]["id"], placed["id"],
        "and it is the same ban: {body}"
    );
    assert_eq!(
        rows[0]["subject"].as_str().expect("subject"),
        "abuser@example.test",
        "the sealed subject is opened for the authorized operator: {body}"
    );
    assert_eq!(
        rows[0]["subject_kind"].as_str().expect("kind"),
        "identifier"
    );

    // A repeat placement on the same subject and path is the conflict, not a duplicate.
    let (status, _, body) = h.post(&bans, "k-create-again", &request).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a second ban on the same subject and path conflicts: {body}"
    );

    // Lift it. The lift reports that something was actually removed.
    let lift = serde_json::json!({
        "subject_kind": "identifier",
        "subject": "abuser@example.test",
        "auth_path": "password"
    })
    .to_string();
    let (status, _, body) = h.post(&format!("{bans}/lift"), "k-lift", &lift).await;
    assert_eq!(status, StatusCode::OK, "the ban is lifted: {body}");
    let first_lift: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        first_lift["lifted"], true,
        "an active ban was actually removed: {body}"
    );

    // And it is gone from the list, which is what proves the DELETE landed rather than
    // the handler merely reporting success.
    let (status, _, body) = h.get(&bans).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        listed["bans"].as_array().expect("bans array").len(),
        0,
        "the lifted ban is gone: {body}"
    );

    // A repeat lift is idempotent and reports that nothing matched.
    let (status, _, body) = h.post(&format!("{bans}/lift"), "k-lift-again", &lift).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a repeat lift is idempotent: {body}"
    );
    let repeat_lift: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        repeat_lift["lifted"], false,
        "nothing matched the second time: {body}"
    );
}

#[tokio::test]
async fn a_ban_placed_on_the_management_plane_is_enforced_by_the_data_plane() {
    // The cross-plane property the grant decision is FOR. A ban the operator places has to
    // be the same ban the login path refuses on, or the management surface is merely
    // writing rows nobody reads. The blind index is derived from the platform master key
    // and the scope, so this also proves the two planes seal and index compatibly.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let bans = format!("/v1/tenants/{tenant}/environments/{environment}/abuse/bans");
    let subject = AbuseSubject {
        kind: AbuseSubjectKind::Ip,
        value: "203.0.113.19".to_owned(),
    };

    // Nothing is banned yet, so the data plane's own check finds nothing.
    let before = h
        .store()
        .scoped(scope)
        .abuse()
        .active_ban(std::slice::from_ref(&subject), AuthPath::Password, 0)
        .await
        .expect("the data-plane ban check reads");
    assert!(before.is_none(), "no ban is in place yet");

    let (status, _, body) = h
        .post(
            &bans,
            "k-enforced",
            &serde_json::json!({
                "subject_kind": "ip",
                "subject": "203.0.113.19",
                "auth_path": "password",
                "reason": "placed by the operator"
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the ban is placed: {body}");

    let after = h
        .store()
        .scoped(scope)
        .abuse()
        .active_ban(std::slice::from_ref(&subject), AuthPath::Password, 0)
        .await
        .expect("the data-plane ban check reads")
        .expect("the data plane sees the operator's ban");
    assert_eq!(
        after.subject, "203.0.113.19",
        "and it opens to the subject the operator banned"
    );
    assert_eq!(after.reason, "placed by the operator");

    // The lift is enforced too: the data plane stops seeing it.
    let (status, _, body) = h
        .post(
            &format!("{bans}/lift"),
            "k-enforced-lift",
            &serde_json::json!({
                "subject_kind": "ip",
                "subject": "203.0.113.19",
                "auth_path": "password"
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the ban is lifted: {body}");
    let lifted = h
        .store()
        .scoped(scope)
        .abuse()
        .active_ban(std::slice::from_ref(&subject), AuthPath::Password, 0)
        .await
        .expect("the data-plane ban check reads");
    assert!(lifted.is_none(), "the data plane stops enforcing it");
}

#[tokio::test]
async fn placing_a_ban_writes_exactly_one_audit_row_and_lifting_writes_another() {
    // The control plane's INSERT on `audit_log` is what makes the ban surface accountable,
    // and an audited write that could not reach the audit relation would fail the whole
    // transaction rather than losing the row quietly. Asserting the rows are there is what
    // distinguishes "the grant is sufficient" from "the grant is sufficient for the read".
    //
    // The scope already carries the audit rows its own creation wrote (a tenant create and
    // the two envelope provisions), so the assertion is on the abuse-family rows exactly,
    // plus a TOTAL that moves by one. Either half alone is weak: the family filter would
    // not notice a second unrelated row the ban path started writing, and the total alone
    // would not notice the ban's row being replaced by something else.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let bans = format!("/v1/tenants/{tenant}/environments/{environment}/abuse/bans");
    let request = serde_json::json!({
        "subject_kind": "ip", "subject": "203.0.113.31", "auth_path": "all"
    })
    .to_string();
    let before = audit_actions(&h, scope).await;
    assert!(
        before.iter().all(|action| !action.starts_with("abuse.")),
        "nothing has audited an abuse action yet: {before:?}"
    );
    // WHERE the scope's envelope key pair was provisioned is pinned rather than
    // tolerated (issue #250). The FIRST seal in a scope lazily provisions it and each
    // provision audits, and since #250 the first seal is the arming of this
    // environment's outbound verification token, which `start_fully_armed` performs
    // before this test runs. So the pair is already in `before`, in order, and the
    // create's delta below is its own row alone. If provisioning ever moved back to
    // the ban path, or stopped happening at all, one of these two halves goes red.
    assert_eq!(
        before
            .iter()
            .filter(|action| action.starts_with("envelope."))
            .cloned()
            .collect::<Vec<String>>(),
        [
            "envelope.kek.provision".to_owned(),
            "envelope.dek.provision".to_owned()
        ],
        "the scope's envelope pair is provisioned exactly once, by the first seal in \
         it (the outbound-verification arming): {before:?}"
    );

    let (status, _, body) = h.post(&bans, "k-audited", &request).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let after_create = audit_actions(&h, scope).await;
    assert_eq!(
        abuse_actions(&after_create),
        vec!["abuse.ban.create".to_owned()],
        "placing a ban writes exactly one abuse audit row"
    );
    // The scope's envelope pair was already provisioned (asserted above), so the
    // create's TOTAL delta is exactly its own row. Pinning the exact sequence rather
    // than the abuse-family filter alone is what would notice the ban path starting to
    // write a second row of some other family.
    assert_eq!(
        &after_create[before.len()..],
        ["abuse.ban.create".to_owned()],
        "the create audits the ban and nothing else"
    );

    let (status, _, body) = h
        .post(&format!("{bans}/lift"), "k-audited-lift", &request)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after_lift = audit_actions(&h, scope).await;
    assert_eq!(
        abuse_actions(&after_lift),
        vec!["abuse.ban.create".to_owned(), "abuse.ban.lift".to_owned()],
        "lifting it writes exactly one more, in order"
    );
    // The envelope is provisioned by now, so the lift's delta is exactly its own row.
    assert_eq!(
        &after_lift[after_create.len()..],
        ["abuse.ban.lift".to_owned()],
        "and the lift adds exactly its own row: {after_lift:?}"
    );

    // A repeat lift matches nothing, so it is a no-op that audits NOTHING. An audit trail
    // that recorded a lift for a ban that was not there would misreport the operator.
    let (status, _, body) = h
        .post(&format!("{bans}/lift"), "k-audited-lift-again", &request)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        audit_actions(&h, scope).await.len(),
        after_lift.len(),
        "a lift that matched nothing writes no audit row"
    );
}

/// The abuse-family audit actions out of a recorded sequence, in order.
fn abuse_actions(actions: &[String]) -> Vec<String> {
    actions
        .iter()
        .filter(|action| action.starts_with("abuse."))
        .cloned()
        .collect()
}

/// Every audit action recorded in `scope`, oldest first, read as the database OWNER so
/// row-level security cannot hide one.
async fn audit_actions(h: &Harness, scope: Scope) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT action FROM audit_log WHERE tenant_id = $1 AND environment_id = $2 \
         ORDER BY recorded_at ASC, id ASC",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(h.db().owner_pool())
    .await
    .expect("read the audit log");
    rows.into_iter().map(|(action,)| action).collect()
}

#[tokio::test]
async fn the_sweep_runs_on_the_production_role_split_and_not_the_dev_fallback() {
    // The load-bearing precondition of every other test in this file, asserted rather than
    // assumed, and the single thing that decides whether any of them can see this defect
    // class at all.
    //
    // A missing control-role grant is observable ONLY when the management plane is
    // connected as `ironauth_control`. In a deployment it is not always: when
    // `admin.control_database_url` is unset and `dev_mode` is on, the control DSN falls
    // back to `database.url`, which puts the management plane on the DATA-plane role.
    // Every dead surface this file repairs works perfectly in that configuration, which is
    // exactly why they shipped. A test harness that quietly did the same thing would be
    // green for the same reason and would prove nothing.
    //
    // So: the DSN every constructor in `tests/common` builds the router's store from is the
    // real `ironauth_control` role, that role is not the data-plane role, and the two
    // genuinely differ in privilege. The third assertion is the one that stops this from
    // being satisfied by two names pointing at one grant set.
    //
    // What this CANNOT catch, stated plainly: a harness change that pointed the router at a
    // full-privilege database would leave all three assertions true, because they are about
    // the DSN rather than about the router. That configuration was measured directly instead
    // (router on the owning role, migration 0098 reverted: all 143 operations pass), which is
    // the masking itself and the reason the defect reached a release.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let control = sqlx::PgPool::connect(h.db().control_url())
        .await
        .expect("connect on the control DSN the router uses");
    let (role,): (String,) = sqlx::query_as("SELECT current_user")
        .fetch_one(&control)
        .await
        .expect("read the connected role");
    assert_eq!(
        role, "ironauth_control",
        "the management router must be driven on the control role, or nothing in this file \
         can observe a control-role privilege"
    );

    let app = sqlx::PgPool::connect(h.db().app_url())
        .await
        .expect("connect on the data-plane DSN");
    let (app_role,): (String,) = sqlx::query_as("SELECT current_user")
        .fetch_one(&app)
        .await
        .expect("read the connected role");
    assert_ne!(
        app_role, role,
        "the dev fallback puts both planes on one role; this harness must not"
    );

    // And the split is a real privilege boundary rather than two names for one grant set.
    // `webauthn_credentials` is a data-plane relation the management surface never reaches,
    // so the data-plane role can address it and the control role cannot.
    let probe = "SELECT count(*) FROM webauthn_credentials";
    sqlx::query(probe)
        .execute(&app)
        .await
        .expect("the data-plane role reads its own relation");
    let refused = sqlx::query(probe).execute(&control).await;
    assert!(
        refused.is_err(),
        "the control role must NOT hold the data plane's privileges; if it does, every \
         assertion in this file about a control-role grant is measuring the wrong role"
    );
}

#[tokio::test]
async fn the_mds3_health_read_reports_the_cache_it_is_asked_about() {
    // The second repaired surface, driven for its REAL answers. It is one endpoint and it
    // only reads, so the thing worth pinning is that it distinguishes the three states an
    // operator asks it about, and that the answer tracks the cache rather than being a
    // constant the missing grant used to make unreachable.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let env = Env::system();
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let health = format!("/v1/tenants/{tenant}/environments/{environment}/webauthn/mds3/health");

    // 1. No cache at all. This is the read that used to be refused outright.
    let (status, _, body) = h.get(&health).await;
    assert_eq!(status, StatusCode::OK, "the health read answers: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["cached"], false, "{body}");
    assert_eq!(view["verdict"], "missing", "{body}");
    assert!(view["blob_no"].is_null(), "{body}");
    assert!(view["entry_count"].is_null(), "{body}");

    // 2. A cached blob whose nextUpdate has not arrived: FRESH, and the read reports the
    //    blob number and the entry count out of the stored payload.
    let far_future = 4_102_444_800_000_000_i64;
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .mds3_blob_cache()
        .upsert(
            &env,
            42,
            far_future,
            &serde_json::json!({ "entries": [{ "aaguid": "a" }, { "aaguid": "b" }] }),
            b"digest-42",
            SEED_MICROS,
            SEED_MICROS,
        )
        .await
        .expect("cache a blob");
    let (status, _, body) = h.get(&health).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["cached"], true, "{body}");
    assert_eq!(view["verdict"], "fresh", "{body}");
    assert_eq!(view["blob_no"], 42, "{body}");
    assert_eq!(
        view["entry_count"], 2,
        "the payload's entries are counted: {body}"
    );
    assert_eq!(view["verified_at_unix_micros"], SEED_MICROS, "{body}");
    assert_eq!(view["next_update_unix_micros"], far_future, "{body}");

    // 3. A cached blob whose nextUpdate has passed: STALE. A newer blob number is what the
    //    sync task writes, so this is reachable without rewinding any clock.
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .mds3_blob_cache()
        .upsert(
            &env,
            43,
            SEED_MICROS,
            &serde_json::json!({ "entries": [] }),
            b"digest-43",
            SEED_MICROS,
            SEED_MICROS,
        )
        .await
        .expect("cache a lapsed blob");
    let (status, _, body) = h.get(&health).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        view["verdict"], "stale",
        "a lapsed nextUpdate reads stale: {body}"
    );
    assert_eq!(view["blob_no"], 43, "{body}");
    assert_eq!(view["entry_count"], 0, "{body}");
}

#[tokio::test]
async fn the_management_plane_cannot_write_the_mds3_cache_it_reads() {
    // The withheld half of the grant, asserted rather than described. The cached metadata
    // is what the passkey attestation gate evaluates against, so a control plane that could
    // write it could weaken attestation for an environment by seeding a forged blob. The
    // grant is SELECT only, and this is what says so in a way that a later widening has to
    // argue with rather than quietly pass.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let env = Env::system();
    let scope = h.outbound_scope();
    let refused = h
        .control_store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .mds3_blob_cache()
        .upsert(
            &env,
            1,
            SEED_MICROS,
            &serde_json::json!({ "entries": [] }),
            b"forged",
            SEED_MICROS,
            SEED_MICROS,
        )
        .await;
    assert!(
        refused.is_err(),
        "the control role holds no write privilege on the metadata cache"
    );
    // And nothing landed: the read still reports no cache.
    let cached = h
        .store()
        .scoped(scope)
        .mds3_blob_cache()
        .get()
        .await
        .expect("the data plane reads the cache");
    assert!(cached.is_none(), "the refused write stored nothing");
}

#[tokio::test]
async fn the_management_plane_cannot_rewrite_a_ban_it_placed() {
    // The withheld half of the ban grant. A ban is immutable once placed: the surface
    // creates one and removes one, and neither ever rewrites one, so UPDATE is deliberately
    // not granted. The point is auditability: a create and a lift each leave a row, while a
    // silent retarget of an existing ban's subject or a silent extension of its expiry
    // would leave none. Without this the withholding is a sentence in a migration comment
    // that nothing measures.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/abuse/bans"),
            "k-immutable",
            &serde_json::json!({
                "subject_kind": "ip", "subject": "203.0.113.44", "auth_path": "password"
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the ban is placed: {body}");

    // Driven as the REAL `ironauth_control` role, over its own connection, which is the
    // only place a privilege is observable at all.
    let control = sqlx::PgPool::connect(h.db().control_url())
        .await
        .expect("connect as the control role");
    let refused = sqlx::query("UPDATE abuse_bans SET expires_at = NULL WHERE tenant_id = $1")
        .bind(scope.tenant().to_string())
        .execute(&control)
        .await;
    assert!(
        refused.is_err(),
        "the control role holds no UPDATE privilege on a placed ban"
    );
}

#[tokio::test]
async fn the_sudo_elevation_answers_against_a_live_environment_when_armed() {
    // The sweep's one blind spot, closed. Sudo mode cannot be armed in the same router as
    // the rest of the surface without gating every mutation behind an elevation, so the
    // sweep drives this route at a router where the feature is OFF, and an off feature
    // answers the uniform not-found BEFORE it resolves anything. That refusal is
    // indistinguishable from a healthy pass, which is precisely the shape of masking this
    // file exists to remove, so the route gets its own armed run.
    //
    // The elevation records a row in `admin_sudo_elevations` and audits it, so a live 200
    // is what proves the control plane can reach both relations.
    let (h, _clock) = Harness::start_with_sudo(300).await;
    let (tenant, environment) = h.create_tenant("sudo", "k-sudo-tenant").await;
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/admin/sudo/elevate"),
            "k-sudo-elevate",
            "",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an armed elevation answers against a live environment: {body}"
    );
}

// ---------------------------------------------------------------------------------------
// The SOFT-DELETED-ENVIRONMENT contract for the whole environment prefix (issues #443,
// #451).
//
// This lives here rather than in a file of its own, and the reason is the defect issue
// #443 names. The sweep below needs three things: one of every row the surface addresses,
// one case per documented operation, and a check that the case list has not drifted from
// the contract. All three already exist in this file, seeded and checked. A second copy
// would be a second inventory to keep in step with the contract, which is the same shape
// as the nine copies of one precondition issue #443 folded together.
// ---------------------------------------------------------------------------------------

/// The uniform not-found EXACTLY as the wire carries it, rendered from the one type that
/// produces it rather than transcribed into a literal here.
///
/// This is what stops a case from passing on the WRONG 404. Axum answers a path that
/// matches no route with a bare 404 and an empty body, so a sweep that asserts only the
/// status cannot tell a real refusal from a request that never reached a handler.
async fn uniform_not_found() -> (StatusCode, BTreeMap<String, Vec<String>>, String) {
    let response = ApiError::NotFound.into_response();
    let status = response.status();
    let headers = header_fields(response.headers());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the not-found body is finite");
    (
        status,
        headers,
        String::from_utf8(bytes.to_vec()).expect("the not-found body is utf-8"),
    )
}

/// A response's headers as a sorted, printable map, so a divergence names the header
/// rather than dumping an opaque `HeaderMap`. The value is a `Vec` because a `HeaderMap`
/// may carry a name more than once, and collapsing to one value would hide exactly the
/// divergence this instrument exists to see.
fn header_fields(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        fields
            .entry(name.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    fields
}

/// Every table's row count, read as the database OWNER so row-level security can never
/// hide a write. The same instrument the two sibling sweeps use.
///
/// The LIMIT is worth stating, because it is the difference between what this measures
/// and what its assertion sounds like. It counts ROWS, not their contents, so a write
/// that mutated a column IN PLACE and wrote nothing else would be invisible to it. What
/// makes it a usable net anyway is that every management write on this surface INSERTs
/// an `audit_log` row in the same transaction as its change, so an in-place update still
/// moves a count. That is a property of the crate's audit contract rather than of this
/// function, and a future write that skipped its audit row would slip through here: the
/// backstop for that one is the audit contract's own tests, not this snapshot. MEASURED:
/// weakening `setClientAllowedScopes`'s pre-write fence to a Read (leaving the post-write
/// re-read a Write, so the response is still the uniform not-found) lands the update in
/// the soft-deleted environment, and the only count that moves is `audit_log`.
async fn snapshot(pool: &sqlx::PgPool) -> BTreeMap<String, i64> {
    let tables: Vec<(String,)> =
        sqlx::query_as("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("list public tables");
    let mut counts = BTreeMap::new();
    for (table,) in tables {
        let (count,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(pool)
            .await
            .expect("count table rows");
        counts.insert(table, count);
    }
    counts
}

/// Every operation the committed contract publishes under the ENVIRONMENT prefix, split
/// by whether it is a GET: the inventory the soft-deleted sweep must cover in full.
///
/// It is derived from the document rather than from the case list, so the two can be
/// required to agree. Deleting a case from [`all_cases`] therefore fails this file twice:
/// once in [`every_documented_operation_is_driven_by_a_case`], which is about the whole
/// contract, and once here, which is about this sweep's own reach.
fn documented_environment_operations() -> (BTreeSet<String>, BTreeSet<String>) {
    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut writes = BTreeSet::new();
    let mut reads = BTreeSet::new();
    for (template, methods) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(ENVIRONMENT_PREFIX) {
            continue;
        }
        for (method, operation) in methods.as_object().expect("operations") {
            let id = operation["operationId"]
                .as_str()
                .expect("every operation carries an id")
                .to_owned();
            if method.eq_ignore_ascii_case("get") {
                reads.insert(id);
            } else {
                writes.insert(id);
            }
        }
    }
    (writes, reads)
}

/// The templated prefix every environment-scoped route hangs off. The trailing slash is
/// load bearing: it excludes the environment's OWN address, so `getEnvironment` and
/// `deleteEnvironment` are outside the sweep rather than inside it.
const ENVIRONMENT_PREFIX: &str = "/v1/tenants/{tenant_id}/environments/{environment_id}/";

/// The operations whose answer at a SOFT-DELETED environment is deliberately NOT the
/// uniform not-found, and the reason each one is exempt.
///
/// Both are POSTs that write NOTHING, which the row snapshot in the sweep proves rather
/// than assumes, and both are the kind of question an operator asks ABOUT a
/// decommissioned environment rather than a mutation of one. Fencing them would close
/// nothing the write fence does not already close and would take away the two things a
/// decommissioned environment is still for.
///
/// The list is a decision record, not a tolerance: a route that stops matching its entry,
/// or a NEW route that answers anything but the refusal, fails the sweep and gets a
/// decision of its own.
fn documented_write_exceptions() -> BTreeMap<&'static str, StatusCode> {
    BTreeMap::from([
        // A pure evaluation of the shipped policies against a submitted hypothetical. It
        // reads no row and writes none, so there is nothing for the environment to be the
        // parent OF. This is the same exemption `tests/absent_environment.rs` grants it,
        // for the same reason and with the same wording.
        ("diagnostics.postFlowDryRun", StatusCode::OK),
        // The EXIT surface. A successor system verifies a credential and reads back the
        // profile so it can migrate the identity out; it writes nothing. Decommissioning
        // an environment is exactly WHEN a successor is draining it, so refusing here
        // would break the migration path at the moment it is needed, and it would do so
        // for a request that changes nothing. It is scope-bound by construction since
        // issue #250 (the token IS that environment's own sealed secret) and authorized
        // by that token, so it is not reachable as a general management route at all.
        //
        // Its 200 is not the whole exemption, and pinning only the 200 left the branch
        // the exemption is FOR undriven: with the fixture user seeded without a password
        // the case answered `{"verified":false}`, which is the negative verdict every
        // wrong password gets and reads no profile at all. The seed carries a real
        // Argon2id verifier and a real claim document now, and
        // [`documented_body_contents`] requires the answer to carry the positive verdict,
        // the subject, and the claim.
        ("migration.verifyMigrationCredential", StatusCode::OK),
        // The OFF SWITCH for the entry above, and the reason it is exempt is the entry
        // above (issue #250). The verify endpoint keeps answering 200 with a live
        // credential oracle inside a soft-deleted environment, deliberately. Fencing the
        // route that DESTROYS that credential therefore turns the soft delete into a one
        // way door: there is no environment-restore route and no generic
        // environment-secrets route, so a decommissioned environment would keep serving a
        // password oracle plus PII with no remedy short of a direct database write.
        //
        // Destroying something is the CLOSING direction, and a closing write never
        // requires its parent to be live. It still requires the parent to EXIST, which is
        // why `tests/absent_environment.rs` drives the same route and requires the uniform
        // not-found there; the store alone would not give that, because deleting a row
        // that was never there violates no foreign key.
        //
        // This is the one exempted write in this file that LANDS A ROW CHANGE, which is
        // the whole point of it, so it is also the one entry in
        // [`documented_write_row_effects`].
        (
            "migration.deleteOutboundVerification",
            StatusCode::NO_CONTENT,
        ),
    ])
}

/// The row-count deltas the documented write exceptions are permitted to leave behind,
/// per table, and nothing else may move (issue #250).
///
/// The sweep's closing claim is that no write into a soft-deleted environment landed a
/// row anywhere, audit log included, read as the database owner so row-level security
/// cannot hide one. Until issue #250 that claim was literally "nothing moved", because
/// both documented exceptions were reads in write clothing.
///
/// `deleteOutboundVerification` is the first exception that is a REAL write, and it has
/// to be: it is the off switch for the credential oracle the exception above it keeps
/// answering with. Tolerating "some rows moved" would delete the whole instrument, so
/// the movement is RECORDED instead, exactly, per table. That turns the assertion from a
/// weaker one into a STRONGER one: it now also pins that the disarm at a soft-deleted
/// environment really did destroy the secret (`environment_secrets` falls by exactly
/// one), really did audit it (`audit_log` rises by exactly one), and really did ANNOUNCE
/// it (`outbox_messages` rises by exactly one). A fence quietly reintroduced on that
/// route would leave all three at zero and fail here.
fn documented_write_row_effects() -> BTreeMap<String, i64> {
    BTreeMap::from([
        // The disarm destroys THIS environment's outbound-verification secret.
        ("environment_secrets".to_owned(), -1),
        // And audits `environment_secret.delete` in the same transaction.
        ("audit_log".to_owned(), 1),
        // And ANNOUNCES it in the same transaction (issue #108), which belongs here for
        // the same reason the exception itself does. A soft-deleted environment KEEPS
        // answering the verify endpoint -- that is why the off switch must not be fenced
        // -- so a consumer mirroring which environments are armed has to learn about the
        // disarm precisely in this case. An event that fired only for LIVE environments
        // would go silent on the one state where the oracle outlives the environment,
        // which is the surprising case rather than the ignorable one.
        //
        // Recorded exactly, like its two neighbours, so this stays an instrument: a
        // producer quietly dropped from the disarm leaves this at zero and fails here,
        // and a write that starts announcing something ELSE shows up as an unexpected
        // row rather than being absorbed by a tolerance.
        ("outbox_messages".to_owned(), 1),
    ])
}

/// The operations whose LIVE answer IS the uniform not-found, so that driving them at a
/// soft-deleted environment measures nothing about the fence, and the reason each one
/// cannot be made to discriminate here.
///
/// Every other case is required to answer something ELSE at a live environment, which is
/// what stops the sweep from passing because its fixture was never satisfiable. That
/// check is the whole difference between this sweep and one that would have stayed green
/// with every fence removed.
fn documented_non_discriminating() -> BTreeSet<&'static str> {
    BTreeSet::from([
        // Sudo mode cannot be armed in this router without gating every other mutation
        // behind an elevation, so the feature is OFF here and the route answers the
        // uniform not-found before it resolves anything, at a live environment and a
        // deleted one alike. `the_sudo_elevation_answers_against_a_live_environment_when_armed`
        // drives it at an armed router; the interaction between an armed elevation and
        // this fence was decided under issue #452 (the privilege check keeps running first,
        // and the challenge's audit row keeps landing) and is described on
        // `ironauth_admin::sudo::require_fresh_privilege`.
        "sudo.elevateAdminSudo",
    ])
}

/// The writes that answer a body-level 400 to a MALFORMED body at a soft-deleted
/// environment rather than the uniform not-found, and the reason each one is exempt.
///
/// All three are CREATES: they address no child row, so the only thing to resolve is the
/// environment itself, and the parent-existence read that fences them sits after the body
/// parse. That ordering is what issue #409 established for the absent-environment fence
/// and neither issue #443 nor #451 touched it, so this list records a shape that was
/// already there rather than a tolerance issued here.
///
/// The reason it is acceptable where `extendSignupQuarantine`'s was not is that these
/// three answer IDENTICALLY at a live environment: 400 there, 400 here, so no caller
/// learns anything about the environment from the answer. What the reordered routes buy
/// on top of that is stronger and separate, namely that nothing at all gets a body-level
/// answer out of a decommissioned environment.
///
/// The list is a decision record, not a tolerance: a NEW route that answers a 400 here
/// fails the sweep and gets a decision of its own.
fn documented_malformed_body_exceptions() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "connectors.createConnector",
        "dcr.createDcrInitialAccessToken",
        "dcr.createDcrPolicy",
    ])
}

/// The READS whose answer changes when the environment is soft-deleted, and why that is
/// correct rather than a fence that leaked onto a GET.
fn documented_read_exceptions() -> BTreeSet<&'static str> {
    BTreeSet::from([
        // Deleting an environment CASCADES `deleted_at` onto its management credentials,
        // which is a deliberate security property and predates all of this: revoking an
        // environment revokes the keys that could act on it. The key row is gone from the
        // repository's point of view, so the read is a not-found for the same reason a
        // revoked key is, and `deleteManagementKey` refuses for that reason too rather
        // than because of the fence. `users`, `organizations`, `connectors`, `permissions`
        // and the rest carry no such cascade, which is the whole mechanism behind issues
        // #411 and #451.
        "keys.getManagementKey",
    ])
}

/// What a case's answer must CARRY, beyond the status it answers with.
///
/// A status alone is not the contract on either half of this sweep, and this is the
/// instrument that says so.
///
/// On the READ half the claim is that a decommissioned environment stays AUDITABLE, and
/// that is a claim about the ROWS. A read that lost its rows and kept its 200 satisfies
/// every status assertion in this file: MEASURED, making `consents::list_user_consents`
/// return `Vec::new()` when the environment read fails left this sweep GREEN, along with
/// `tests/consents.rs`, `tests/users.rs` and `tests/deleted_environment.rs`. The whole
/// justification for leaving reads unfenced rests on the listings still answering with
/// their contents, so at least the listings that carry a row have to be checked for it.
///
/// On the WRITE half the same problem has one instance, and it is the exemption rather
/// than a refusal: `verifyMigrationCredential` is exempt BECAUSE a successor draining the
/// environment reads back the subject and the profile, so pinning only its 200 leaves the
/// branch the exemption exists for undriven.
///
/// It is a SUBSET rather than every case, because each entry has to name a value the
/// fixture genuinely seeds, and most cases here address a resource whose id the case list
/// already spells into the path. The organization subtree gets the exhaustive version of
/// this in `tests/deleted_environment.rs`, with the same substring idiom over identifiers
/// that are freshly generated per run and appear nowhere else in a response.
fn documented_body_contents(f: &Fixture) -> BTreeMap<&'static str, Vec<String>> {
    BTreeMap::from([
        // The user page and the single user, by the id of the seeded row.
        ("users.listUsers", vec![f.user.clone()]),
        ("users.getUser", vec![f.user.clone()]),
        // The connected app, by client id: the one field the list exists to name.
        ("consents.listUserConsents", vec![f.client.clone()]),
        // The seeded trust anchor and its mapping, by row id. A decommissioned environment
        // has to stay auditable through exactly these two: an operator answering "whose
        // signature could mint a token here" after the fact reads them, and a 200 carrying an
        // emptied array would answer that question wrongly rather than not at all.
        (
            "external_issuers.listExternalIssuers",
            vec![f.external_issuer.clone()],
        ),
        (
            "external_issuers.listSubjectMappings",
            vec![f.subject_mapping.clone()],
        ),
        // The POSITIVE verdict, the subject it carries, and the PII inside the profile.
        (
            "migration.verifyMigrationCredential",
            vec![
                "\"verified\":true".to_owned(),
                f.user.clone(),
                MIGRATION_CLAIM.to_owned(),
            ],
        ),
    ])
}

/// The expected strings a body failed to carry, if any.
fn missing_contents<'a>(body: &str, expected: &'a [String]) -> Vec<&'a str> {
    expected
        .iter()
        .filter(|value| !body.contains(value.as_str()))
        .map(String::as_str)
        .collect()
}

/// Delete an environment through the management API, exactly as an operator would.
async fn soft_delete_environment(h: &Harness, tenant: &str, environment: &str) {
    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the environment soft-deletes: {body}"
    );
    // And it really is gone as far as every reader is concerned, so the pass below is
    // measuring a deleted environment rather than a delete that quietly did nothing.
    let (status, _, body) = h
        .get(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a soft-deleted environment reads as absent: {body}"
    );
}

/// Drive every environment-prefixed case at the LIVE control environment and record the
/// status each one answered.
///
/// This is the anti-vacuity instrument the sweep turns on: a case whose live answer is
/// already the uniform not-found could never have measured the fence at a deleted
/// environment, and the sweep requires such a case to be one of the documented
/// non-discriminating entries rather than silently passing.
///
/// It is the anti-vacuity instrument for the BODY expectations too. A case whose contents
/// are pinned has to carry them HERE, at a live environment, which is what makes the same
/// assertion at the deleted environment attributable to the deletion: an expectation the
/// fixture never satisfied fails on this pass rather than being reported as a content
/// regression that had nothing to do with the environment.
async fn control_answers(
    control: &Harness,
    fixture: &Fixture,
    base: &str,
) -> BTreeMap<String, StatusCode> {
    let contents = documented_body_contents(fixture);
    let mut live = BTreeMap::new();
    for (index, case) in all_cases(fixture).iter().enumerate() {
        if !case.path.starts_with(base) {
            continue;
        }
        let (status, body) = drive(control, case, &format!("k-control-{index}")).await;
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{} is not routed at the method this sweep drives: {body}",
            case.label
        );
        if let Some(expected) = contents.get(case.label) {
            let missing = missing_contents(&body, expected);
            assert!(
                missing.is_empty(),
                "{} answered {status} at a LIVE environment without carrying {missing:?}, so \
                 the same expectation at a soft-deleted one would measure the fixture rather \
                 than the fence: {body}",
                case.label
            );
        }
        live.insert(case.label.to_owned(), status);
    }
    live
}

/// Drive every environment-prefixed GET at the soft-deleted environment and require each
/// answer to match the one the LIVE control gave.
///
/// This is the half of the contract that says a decommissioned environment stays
/// AUDITABLE, and it is asserted rather than assumed because a fence that leaked onto a
/// read would otherwise look exactly like a fence that worked. Returns the observed
/// table, the divergences, and the set of operations actually driven.
///
/// The status is compared for every read and the BODY for the subset
/// [`documented_body_contents`] names, and the second half is not optional polish: a 200
/// carrying nothing is not an audit, and an emptied listing keeps its status.
async fn read_pass(
    doomed: &Harness,
    cases: &[Case],
    base: &str,
    live: &BTreeMap<String, StatusCode>,
    contents: &BTreeMap<&'static str, Vec<String>>,
) -> (Vec<String>, Vec<String>, BTreeSet<String>) {
    let exceptions = documented_read_exceptions();
    let mut observed = Vec::new();
    let mut wrong = Vec::new();
    let mut driven = BTreeSet::new();
    for (index, case) in cases.iter().enumerate() {
        if !case.path.starts_with(base) || case.method != "GET" {
            continue;
        }
        driven.insert(operation_of(case).to_owned());
        let (status, body) = drive(doomed, case, &format!("k-read-{index}")).await;
        let expected = live.get(case.label).copied().expect("a control answer");
        observed.push(format!("{:7} {:55} {status}", case.method, case.label));
        if exceptions.contains(case.label) {
            continue;
        }
        if status != expected {
            wrong.push(format!(
                "{} answered {status} for a READ of a soft-deleted environment, expected the \
                 live answer {expected}: {body}",
                case.label
            ));
            continue;
        }
        if let Some(expected_contents) = contents.get(case.label) {
            let missing = missing_contents(&body, expected_contents);
            if !missing.is_empty() {
                wrong.push(format!(
                    "{} answered {status} for a READ of a soft-deleted environment but did not \
                     carry {missing:?}, so the environment is not AUDITABLE through it and the \
                     status is the only thing that survived: {body}",
                    case.label
                ));
            }
        }
    }
    (observed, wrong, driven)
}

/// Require the sweep to have driven EVERY operation the committed contract publishes
/// under the environment prefix, in both directions.
///
/// This is what stops the sweep from shrinking. A case removed from [`all_cases`] stops
/// being driven here, and a new environment-scoped route is undriven the moment it is
/// documented.
fn assert_sweep_reaches_the_whole_prefix(
    driven: &BTreeSet<String>,
    driven_reads: &BTreeSet<String>,
) {
    let (documented_writes, documented_reads) = documented_environment_operations();
    assert_eq!(
        driven,
        &documented_writes,
        "the committed contract publishes {} environment-scoped writes and this sweep drives \
         {}; the difference is what nothing measures at a soft-deleted environment",
        documented_writes.len(),
        driven.len()
    );
    assert_eq!(
        driven_reads,
        &documented_reads,
        "the committed contract publishes {} environment-scoped reads and this sweep drives {}",
        documented_reads.len(),
        driven_reads.len()
    );
}

/// Require every refusal to be the SAME refusal, headers included.
///
/// Two things, because neither alone is the claim: every refusal carries every header the
/// ONE renderer emits (which rules out axum's bare 404 for a path that reached no
/// handler), and all of the refusals carry the same headers as each other down to the
/// middleware's stamp (which rules out one route adding or dropping a header the other
/// sixty do not, something no comparison against the bare rendered error could see).
fn assert_every_refusal_is_the_same_refusal(
    refusals: &[(&str, BTreeMap<String, Vec<String>>)],
    not_found_headers: &BTreeMap<String, Vec<String>>,
) {
    let (canonical, canonical_headers) = refusals
        .first()
        .map(|(label, fields)| (*label, fields.clone()))
        .expect("the sweep drives at least one refusal");
    for (name, values) in not_found_headers {
        assert_eq!(
            canonical_headers.get(name),
            Some(values),
            "{canonical} answered a refusal whose `{name}` is not the one the uniform \
             not-found renders: {canonical_headers:?}"
        );
    }
    for (label, fields) in refusals {
        assert_eq!(
            fields, &canonical_headers,
            "{label} refused with different headers from {canonical}"
        );
    }
}

/// The tables whose row count MOVED between two snapshots, and by how much.
///
/// `assert_eq!(before, after)` over the whole map already FAILS when a write lands, so
/// this changes nothing about the verdict; it changes what the failure says. The map
/// carries a count for every table in the schema, so the equality failure prints two
/// hundred-odd unchanged pairs and names nothing, and the reader is left to find the
/// surface by rereading the driven table. Naming the moved tables points at it directly:
/// `audit_log` alone says a write landed and its action names the route, and a resource
/// table beside it names the resource outright.
///
/// MEASURED against exactly the mutant [`snapshot`] describes: the failure reads
/// `audit_log: 1` and nothing else, where the equality failure it replaced named no
/// table at all.
///
/// It returns the DELTA rather than a rendered line so the caller can compare it against
/// [`documented_write_row_effects`], which is what lets one documented exception be a
/// real write without the instrument degrading to "some rows moved, fine".
fn moved_deltas(
    before: &BTreeMap<String, i64>,
    after: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    let mut moved = BTreeMap::new();
    for (table, before_count) in before {
        let after_count = after.get(table).copied().unwrap_or_default();
        if after_count != *before_count {
            moved.insert(table.clone(), after_count - before_count);
        }
    }
    for (table, after_count) in after {
        if !before.contains_key(table) {
            moved.insert(table.clone(), *after_count);
        }
    }
    moved
}

/// The `operationId` half of a case's `module.operationId` label.
fn operation_of(case: &Case) -> &'static str {
    case.label
        .rsplit('.')
        .next()
        .expect("a case label names an operation")
}

/// One ordering probe: a route, the id it addresses, a body the handler must REFUSE at
/// the body level, and the status each of the two environments must answer.
struct OrderingProbe {
    what: &'static str,
    path: fn(&Fixture) -> String,
    body: &'static str,
    live: StatusCode,
    deleted: StatusCode,
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_address_is_resolved_before_the_body_on_the_two_reordered_writes() {
    // The ORDERING contract for `setUserState` and `extendSignupQuarantine`, written down
    // as statuses because the comments on both handlers now make a claim about exactly
    // these cells and a comment is not a measurement.
    //
    // The sweep's malformed-body pass above already pins the deleted column for every
    // JSON-bodied write. What it cannot pin is the LIVE column, and the live column is
    // where the interesting half of this ordering lives: the body is STILL validated at a
    // live environment (so the fence did not swallow the 400 wholesale), and an
    // unaddressable user id now beats a malformed body (so the wire changed, in a way
    // worth writing down rather than discovering later).
    let control = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let control_fixture = Fixture::seed(&control).await;
    let doomed = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let fixture = Fixture::seed(&doomed).await;
    soft_delete_environment(&doomed, &fixture.tenant, &fixture.environment).await;

    let probes = [
        // A user that EXISTS, and a body that does not parse. The 400 at a live
        // environment is what says the body is still checked; the 404 at a deleted one is
        // the whole point of the reorder.
        OrderingProbe {
            what: "setUserState, addressable user, malformed body",
            path: |f| {
                format!(
                    "/v1/tenants/{}/environments/{}/users/{}/state",
                    f.tenant, f.environment, f.user
                )
            },
            body: "{",
            live: StatusCode::BAD_REQUEST,
            deleted: StatusCode::NOT_FOUND,
        },
        // The DOCUMENTED wire change: an unaddressable user id plus a malformed body
        // answered 400 before this change and answers the not-found now, at a LIVE
        // environment. The address wins.
        OrderingProbe {
            what: "setUserState, unaddressable user, malformed body",
            path: |f| {
                format!(
                    "/v1/tenants/{}/environments/{}/users/not-a-user-id/state",
                    f.tenant, f.environment
                )
            },
            body: "{",
            live: StatusCode::NOT_FOUND,
            deleted: StatusCode::NOT_FOUND,
        },
        OrderingProbe {
            what: "extendSignupQuarantine, malformed body",
            path: |f| {
                format!(
                    "/v1/tenants/{}/environments/{}/signup-quarantine/{}/extend",
                    f.tenant, f.environment, f.quarantined_user
                )
            },
            body: "{",
            live: StatusCode::BAD_REQUEST,
            deleted: StatusCode::NOT_FOUND,
        },
        // The route's own field-level refusal, which is the second 400 a decommissioned
        // environment used to answer.
        OrderingProbe {
            what: "extendSignupQuarantine, zero window",
            body: "{\"extend_secs\":0}",
            path: |f| {
                format!(
                    "/v1/tenants/{}/environments/{}/signup-quarantine/{}/extend",
                    f.tenant, f.environment, f.quarantined_user
                )
            },
            live: StatusCode::BAD_REQUEST,
            deleted: StatusCode::NOT_FOUND,
        },
    ];

    let mut wrong: Vec<String> = Vec::new();
    for (index, probe) in probes.iter().enumerate() {
        for (name, h, f, expected) in [
            ("LIVE", &control, &control_fixture, probe.live),
            ("DELETED", &doomed, &fixture, probe.deleted),
        ] {
            let case = Case {
                label: "ordering.probe",
                method: "POST",
                path: (probe.path)(f),
                body: Some(probe.body.to_owned()),
                content_type: "application/json",
                token: OPERATOR_TOKEN,
            };
            let (status, body) = drive(h, &case, &format!("k-order-{index}-{name}")).await;
            if status != expected {
                wrong.push(format!(
                    "{} at a {name} environment answered {status}, expected {expected}: {body}",
                    probe.what
                ));
            }
        }
    }

    // And the ONE 400 that deliberately survives at a decommissioned environment: the
    // Idempotency-Key precondition. It runs ahead of the fence because a genuine replay
    // has to keep working across the deletion (issue #411), so a POST with no key is told
    // so rather than told not-found, and it is told so identically at both environments.
    // Both handlers' comments say this; this is where it is measured.
    for (name, h, f) in [
        ("LIVE", &control, &control_fixture),
        ("DELETED", &doomed, &fixture),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/tenants/{}/environments/{}/users/{}/state",
                f.tenant, f.environment, f.user
            ))
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .expect("request builds");
        let (status, _, body) = h.send(request).await;
        if status != StatusCode::BAD_REQUEST
            || !body.contains("the Idempotency-Key header is required on POST")
        {
            wrong.push(format!(
                "setUserState with no Idempotency-Key at a {name} environment answered {status} \
                 {body}, expected the 400 that says the header is required"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "the address-before-body ordering does not hold:\n{}",
        wrong.join("\n")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn every_environment_scoped_write_refuses_a_soft_deleted_environment() {
    // The whole-surface soft-deleted contract (issues #443, #451), driven at TWO
    // identically configured routers over two identically seeded environments. The only
    // difference between them is the DELETE, which is what makes every divergence below
    // attributable to it and nothing else.
    //
    // A single environment cannot do this. The writes CONSUME what they address (a delete
    // removes its row, a queue decision consumes its case), so a second pass over one
    // fixture would answer 404 for reasons that have nothing to do with the environment,
    // and a sweep cannot tell that apart from a fence. That is the exact shape of vacuity
    // this file has already been caught by once: `deleteSignupForm` and
    // `deleteClientAdminConsent` refused a deleted environment while UNFENCED, because the
    // PUT that would have created the row they address had itself been refused. Both rows
    // are seeded in `Fixture::seed` now, and both cases are discriminating.
    let control = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let control_fixture = Fixture::seed(&control).await;
    let doomed = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let fixture = Fixture::seed(&doomed).await;

    let control_base = format!(
        "/v1/tenants/{}/environments/{}/",
        control_fixture.tenant, control_fixture.environment
    );
    let base = format!(
        "/v1/tenants/{}/environments/{}/",
        fixture.tenant, fixture.environment
    );

    let live = control_answers(&control, &control_fixture, &control_base).await;

    soft_delete_environment(&doomed, &fixture.tenant, &fixture.environment).await;

    let (not_found_status, not_found_headers, not_found_body) = uniform_not_found().await;
    let write_exceptions = documented_write_exceptions();
    let non_discriminating = documented_non_discriminating();

    // The READS first, and the row snapshot AFTER them. A read is not free of side
    // effects on this surface: `exportIdentities` writes a `user.export` audit row by
    // design, and it must keep doing so, so the zero-write claim below is about the
    // WRITES and is measured over exactly them.
    let cases = all_cases(&fixture);
    let contents = documented_body_contents(&fixture);
    let mut driven: BTreeSet<String> = BTreeSet::new();
    let (mut observed, mut wrong, driven_reads) =
        read_pass(&doomed, &cases, &base, &live, &contents).await;

    let before = snapshot(doomed.db().owner_pool()).await;

    // The WRITES.
    let mut refusals: Vec<(&str, BTreeMap<String, Vec<String>>)> = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        if !case.path.starts_with(&base) || case.method == "GET" {
            continue;
        }
        driven.insert(operation_of(case).to_owned());
        let (status, headers, body) =
            drive_observed(&doomed, case, &format!("k-write-{index}")).await;
        observed.push(format!("{:7} {:55} {status}", case.method, case.label));
        let live_answer = live.get(case.label).copied().expect("a control answer");
        if non_discriminating.contains(case.label) {
            if live_answer != not_found_status {
                wrong.push(format!(
                    "{} answers {live_answer} at a LIVE environment, so it DOES discriminate \
                     and must not be listed in documented_non_discriminating",
                    case.label
                ));
            }
        } else if live_answer == not_found_status {
            wrong.push(format!(
                "{} answers the uniform not-found at a LIVE environment too, so driving it at \
                 a soft-deleted one measures nothing about the fence; make the fixture satisfy \
                 it or document why it cannot",
                case.label
            ));
        }
        if let Some(&expected) = write_exceptions.get(case.label) {
            if status != expected {
                wrong.push(format!(
                    "{} answered {status}, expected the documented exception {expected}: {body}",
                    case.label
                ));
            } else if let Some(expected_contents) = contents.get(case.label) {
                // And the exemption's own BRANCH was driven. An exception pinned by its
                // status alone says only that the route was not fenced; it says nothing
                // about the code path the exemption was granted FOR.
                let missing = missing_contents(&body, expected_contents);
                if !missing.is_empty() {
                    wrong.push(format!(
                        "{} answered its documented exception {status} at a soft-deleted \
                         environment but did not carry {missing:?}, so the branch the exemption \
                         exists for was never driven: {body}",
                        case.label
                    ));
                }
            }
            continue;
        }
        if status != not_found_status || body != not_found_body {
            wrong.push(format!(
                "{} answered {status} for a WRITE into a soft-deleted environment, expected the \
                 uniform not-found: {body}",
                case.label
            ));
            continue;
        }
        refusals.push((case.label, header_fields(&headers)));
    }

    // And the same writes again with a MALFORMED body, which is a different question and
    // was a different answer.
    //
    // Everything above drives a WELL FORMED request, so all it can say is that a
    // well-formed write is refused. A handler that validates its body BEFORE it resolves
    // its parent answers the body-level 400 instead, and "every environment-scoped write
    // answers the uniform not-found" is then true only of the requests the sweep happens
    // to send. MEASURED before this pass existed: `extendSignupQuarantine` answered 400
    // `bad_request` to a malformed body and 400 "extend_secs must be at least 1" to
    // `{"extend_secs":0}` at a soft-deleted environment, while `approveSignupQuarantine`
    // and `rejectSignupQuarantine` next door answered the refusal. Nothing in this file
    // could see it.
    let malformed_exceptions = documented_malformed_body_exceptions();
    for (index, case) in cases.iter().enumerate() {
        if !case.path.starts_with(&base) || case.method == "GET" {
            continue;
        }
        // Only the JSON-bodied writes: a route that takes no body cannot be sent a
        // malformed one, and the two octet-stream uploads have no parse step to order
        // against (their sniff is over the BYTES).
        if case.body.is_none() || case.content_type != "application/json" {
            continue;
        }
        // The two documented write exceptions answer their exception rather than the
        // refusal by design, and the non-discriminating route answers the refusal for a
        // reason that has nothing to do with the environment. Neither measures anything
        // here.
        if write_exceptions.contains_key(case.label) || non_discriminating.contains(case.label) {
            continue;
        }
        let probe = Case {
            label: case.label,
            method: case.method,
            path: case.path.clone(),
            // An empty object that never closes: rejected by every body parser on the
            // surface, at the parse rather than at a field, so no route can be refusing
            // it for a reason of its own.
            body: Some("{".to_owned()),
            content_type: case.content_type,
            token: case.token,
        };
        let (status, body) = drive(&doomed, &probe, &format!("k-malformed-{index}")).await;
        observed.push(format!(
            "{:7} {:55} {status} (malformed body)",
            case.method, case.label
        ));
        if malformed_exceptions.contains(case.label) {
            continue;
        }
        if status != not_found_status || body != not_found_body {
            wrong.push(format!(
                "{} answered {status} to a MALFORMED body at a soft-deleted environment, so it \
                 validates the body before it resolves the environment and the refusal above is \
                 true only of well formed requests: {body}",
                case.label
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "the environment surface disagrees about a soft-deleted environment:\n{}\n\nthe whole \
         table:\n{}",
        wrong.join("\n"),
        observed.join("\n")
    );

    assert_sweep_reaches_the_whole_prefix(&driven, &driven_reads);
    assert_every_refusal_is_the_same_refusal(&refusals, &not_found_headers);

    // And the ONLY rows that moved anywhere, audit log included, are the ones the
    // documented exceptions are documented to move. Read as the database owner, so
    // row-level security cannot hide one. It covers the refusals and the exceptions
    // alike: the claim that the flow dry run and the credential verification write
    // nothing is measured here rather than asserted in their comments, and so is the
    // claim that the disarm really does destroy the credential and audit it.
    let after = snapshot(doomed.db().owner_pool()).await;
    let moved = moved_deltas(&before, &after);
    assert_eq!(
        moved,
        documented_write_row_effects(),
        "the rows a soft-deleted environment's writes moved are not exactly the documented \
         effects of the documented exceptions. Anything unexpected here is a write that \
         LANDED; a documented effect that is MISSING is an exception whose branch never \
         ran (a fence quietly reintroduced on the disarm reads exactly that way).\n\nthe \
         whole table:\n{}",
        observed.join("\n")
    );
}

#[tokio::test]
async fn a_retried_ban_and_lift_replay_their_original_responses() {
    // The two abuse-ban routes gained Idempotency-Key handling. Each has a DIFFERENT
    // failure without it, and both are asserted here rather than assumed symmetric.
    let h = Harness::start_fully_armed(50, OUTBOUND_TOKEN).await;
    let scope = h.outbound_scope();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/abuse");
    let bans = format!("{base}/bans");
    let lift = format!("{base}/bans/lift");
    let place = serde_json::json!({
        "subject_kind": "ip",
        "subject": "203.0.113.77",
        "auth_path": "password",
        "reason": "placed by the operator"
    })
    .to_string();

    let (status, _, first) = h.post(&bans, "ban-key", &place).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let first_view: serde_json::Value = serde_json::from_str(&first).expect("json");

    // WITHOUT the key handling this retry answers 409 `already banned`, which reads as
    // somebody else's ban rather than the caller's own. It now replays the 201.
    let (status, _, replayed) = h.post(&bans, "ban-key", &place).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a retried place replays: {replayed}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&replayed).expect("json"),
        first_view,
        "including the ban id, so the caller can address what it created"
    );

    // A DIFFERENT key genuinely re-executes and hits the real conflict, which is what
    // shows the replay above was a stored response rather than the route having gone
    // quietly permissive.
    let (status, _, conflict) = h.post(&bans, "ban-key-2", &place).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a fresh key still meets the duplicate-ban conflict: {conflict}"
    );

    let drop_it = serde_json::json!({
        "subject_kind": "ip",
        "subject": "203.0.113.77",
        "auth_path": "password"
    })
    .to_string();
    let (status, _, lifted) = h.post(&lift, "lift-key", &drop_it).await;
    assert_eq!(status, StatusCode::OK, "{lifted}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lifted).expect("json")["lifted"],
        true
    );

    // The lift's failure mode is the opposite one: re-executing finds the ban already
    // gone and reports `lifted: false` for the request that lifted it. The replay must
    // still say true.
    let (status, _, lift_replay) = h.post(&lift, "lift-key", &drop_it).await;
    assert_eq!(status, StatusCode::OK, "{lift_replay}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lift_replay).expect("json")["lifted"],
        true,
        "the replay reports what the original lift did, not what a rerun would find"
    );

    // The control: a fresh key re-executes and truthfully reports nothing left to lift.
    let (status, _, rerun) = h.post(&lift, "lift-key-2", &drop_it).await;
    assert_eq!(status, StatusCode::OK, "{rerun}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&rerun).expect("json")["lifted"],
        false,
        "so the replay above genuinely differed from a rerun"
    );
}
