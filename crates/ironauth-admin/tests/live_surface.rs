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

mod common;

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, OPERATOR_TOKEN, bearer};
use ironauth_env::Env;
use ironauth_store::{
    AbuseSubject, AbuseSubjectKind, AuthPath, CorrelationId, MigrationKind, NewMigrationRun,
    NewRecoveryFlow, NewResourceServer, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, Scope,
    SignupQuarantineReason, TokenFormat,
};

/// The COMMITTED management contract, embedded at compile time: the same artifact and the
/// same idiom `absent_environment.rs` and `openapi_contract.rs` use.
const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");

/// The shared bearer the outbound verification endpoint is configured with.
const OUTBOUND_TOKEN: &str = "outbound-sweep-token";

/// The smallest byte string the brand-asset upload's MAGIC-BYTE sniff accepts: a RIFF
/// container tagged WEBP. The sniff reads the BYTES and never the declared header.
const RASTER_UPLOAD: &str = "RIFF\0\0\0\0WEBP";

/// A fixed, plausible instant for every seeded row, in Unix microseconds.
const SEED_MICROS: i64 = 1_700_000_000_000_000;

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
    connector: String,
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

        let (status, _, body) = h
            .post(
                &format!("{base}/users"),
                "seed-user",
                &serde_json::json!({ "identifier": "sweep@example.test" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create user: {body}");
        let user = field(&body, "/id", "seed user");

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

        // Every day-one algorithm, so the compatibility wizard resolves this issuer as
        // fully provisioned and the signing-algorithm pin reaches its write.
        h.provision_all_algorithms(scope).await;

        // The data-plane rows the management surface can read and revoke but never mint:
        // a dynamically registered client, a live session, and its refresh family.
        let client = h.seed_quarantined_dcr_client(scope).await.to_string();
        let session = h.seed_session(scope, &user).await;
        let family = h
            .seed_refresh_family(scope, &user, &client, &session, false)
            .await
            .to_string();
        let session = session.to_string();

        let actor = h.test_actor(&env);

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

        Self {
            tenant,
            environment,
            doomed_tenant,
            doomed_environment,
            operator,
            client,
            connector,
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
            quarantined_user,
            flow_version,
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
        connector,
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
        quarantined_user,
        second_quarantined_user,
        unenrolled_user,
        recovery_flow_to_reject,
        observed_flow,
        brand_slug,
        snapshot,
        base_revision,
        flow_version,
    } = f;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let org_base = format!("{base}/organizations/{organization}");
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
        Case::empty(
            "tenants.restoreTenant",
            "POST",
            format!("/v1/tenants/{doomed_tenant}/restore"),
        ),
    ]
}

/// Drive one case with the bootstrap operator token, carrying an Idempotency-Key on every
/// request (the routes that require one get it; the rest ignore it).
async fn drive(h: &Harness, case: &Case, key: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(case.method)
        .uri(&case.path)
        .header(header::AUTHORIZATION, bearer(case.token))
        .header("idempotency-key", key)
        .header(header::CONTENT_TYPE, case.content_type)
        .body(case.body.clone().map_or_else(Body::empty, Body::from))
        .expect("request builds");
    let (status, _, body) = h.send(request).await;
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
        connector: "con_0".to_owned(),
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
        quarantined_user: "usr_1".to_owned(),
        second_quarantined_user: "usr_2".to_owned(),
        unenrolled_user: "usr_3".to_owned(),
        recovery_flow_to_reject: "rcf_1".to_owned(),
        observed_flow: "flw_0".to_owned(),
        brand_slug: "default".to_owned(),
        snapshot: "{}".to_owned(),
        base_revision: "0".to_owned(),
        flow_version: 1,
    };
    let cases = all_cases(&fixture);
    let documented = documented_operations();

    // 1. Every case addresses exactly ONE documented operation, and its label names that
    //    operation. A case whose path has a typo in a LITERAL segment matches no template
    //    at all and fails here, which is the hole a status-only sweep cannot see: axum
    //    answers an unrouted path with a 404, and a 404 is not a server error.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for case in &cases {
        let addressed: Vec<&DocumentedOperation> = documented
            .iter()
            .filter(|op| op.method == case.method && template_matches(&op.template, &case.path))
            .collect();
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

    let (status, _, body) = h.post(&bans, "k-audited", &request).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let after_create = audit_actions(&h, scope).await;
    assert_eq!(
        abuse_actions(&after_create),
        vec!["abuse.ban.create".to_owned()],
        "placing a ban writes exactly one abuse audit row"
    );
    // The FIRST seal in a scope lazily provisions its envelope key pair, and each
    // provision audits, so the create's total delta is three rather than one. That is
    // measured rather than tolerated: pinning the exact sequence is what would notice the
    // ban path starting to write a fourth row, and what would notice the envelope
    // provisioning moving somewhere a ban no longer triggers it.
    assert_eq!(
        &after_create[before.len()..],
        [
            "envelope.kek.provision".to_owned(),
            "envelope.dek.provision".to_owned(),
            "abuse.ban.create".to_owned()
        ],
        "the create audits its envelope provisioning and then the ban, and nothing else"
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
