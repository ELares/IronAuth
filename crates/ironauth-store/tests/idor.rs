// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cross-tenant and cross-environment IDOR harness, against a real
//! database, over every scoped-repository operation that exists today.

use ironauth_env::Env;
use ironauth_store::idor_harness::{IdorHarness, UPSTREAM_TOKEN_PROBE_CONNECTOR};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, ConnectorCapabilities, ConnectorId, CorrelationId,
    CredentialType, FederationLoginStateId, GrantId, IssueCode, NewConnector,
    NewFederationLoginState, NewRefreshFamily, NewSession, NewUpstreamTokens, RefreshFamilyId,
    RefreshTokenId, Scope, SessionId, StoreError, UpstreamTokenId, UserId, refresh_token_digest,
};

/// A timestamp far past any test's clock, so a planted fixture never expires mid-test.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

#[tokio::test]
async fn idor_harness_denies_cross_tenant_and_cross_environment_uniformly() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Caller is tenant A, environment A1. Victims: tenant B, and a SECOND
    // environment of tenant A (cross-environment is a distinct probe).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    // Plant a victim client in each foreign scope (writes need an acting context).
    let victim_b = db
        .store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "victim in tenant B")
        .await
        .expect("create victim B");
    let victim_a2 = db
        .store()
        .scoped(scope_a2)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "victim in environment A2")
        .await
        .expect("create victim A2");

    // A well-formed identifier in the caller's OWN scope that was never stored.
    let absent_in_a = ClientId::generate(&env, &scope_a).to_string();

    // Baseline for uniformity: in its own scope the caller gets NotFound for the
    // absent identifier. This is the response every foreign probe must match.
    let clients_a = db.store().scoped(scope_a).clients();
    let absent_id = clients_a
        .parse_id(&absent_in_a)
        .expect("absent identifier is well formed and in scope");
    assert!(matches!(
        clients_a.get(&absent_id).await,
        Err(StoreError::NotFound)
    ));

    // Run every registered store probe against the foreign identifiers.
    let mut harness = IdorHarness::new();
    harness.register_store_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["clients.get", "clients.delete"],
        "every scoped-repository resolve-by-id operation is registered"
    );

    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        // The absent id is included so a leak would show up as a false Denied
        // nowhere and the run stays a strict superset of the real attack.
        absent_in_a.clone(),
    ];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &foreign_refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The delete probe must not have leak-deleted the victims: they survive.
    assert!(
        db.store()
            .scoped(scope_b)
            .clients()
            .get(&victim_b)
            .await
            .is_ok(),
        "tenant B's client must survive the delete probe"
    );
    assert!(
        db.store()
            .scoped(scope_a2)
            .clients()
            .get(&victim_a2)
            .await
            .is_ok(),
        "environment A2's client must survive the delete probe"
    );

    // Uniformity at the parse boundary: a cross-tenant identifier and a
    // cross-environment identifier both fail exactly like an absent one.
    assert!(
        matches!(
            clients_a.parse_id(&victim_b.to_string()),
            Err(StoreError::NotFound)
        ),
        "cross-tenant identifier must parse to the uniform NotFound"
    );
    assert!(
        matches!(
            clients_a.parse_id(&victim_a2.to_string()),
            Err(StoreError::NotFound)
        ),
        "cross-environment identifier must parse to the uniform NotFound"
    );
}

#[tokio::test]
async fn session_fleet_surfaces_are_cross_tenant_and_cross_environment_isolated() {
    // Every fleet-operations surface of the two-tier session model (issue #32) is
    // registered with the harness and must deny a foreign identifier uniformly: the
    // authentication read path, the per-client sid store, the fleet read surfaces
    // (by-id AND list), and the three mutating revoke surfaces. The bulk revoke is the
    // sharp MUTATING one (a foreign session smuggled into an otherwise valid batch must
    // be a no-op); the two LIST surfaces are the sharp READING ones, because a list has
    // no identifier to fence on and would leak a whole foreign tenant at once.
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    // Plant a victim session (and a per-client session on it) in each foreign scope.
    let victim_b = plant_session(&db, &env, scope_b).await;
    let victim_a2 = plant_session(&db, &env, scope_a2).await;
    // Plant a victim refresh FAMILY too, so the refresh-family probes have a real
    // foreign row of their OWN type to hunt for: without one, every rff_ probe would
    // trivially pass on a ses_ id that cannot even parse as a family id, and the family
    // list probe would be vacuous.
    let victim_family_b = plant_refresh_family(&db, &env, scope_b, &victim_b).await;

    let mut harness = IdorHarness::new();
    harness.register_session_fleet_probes();
    assert_eq!(
        harness.probe_names(),
        vec![
            "sessions.get",
            "client_sessions.ensure_sid",
            "session_fleet.get",
            "session_fleet.list",
            "refresh_family_fleet.get",
            "refresh_family_fleet.list",
            "sessions.revoke",
            "sessions.bulk_revoke",
            "sessions.revoke_all",
        ],
        "every session fleet-ops surface is registered with the harness"
    );

    let absent_in_a = SessionId::generate(&env, &scope_a).to_string();
    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        victim_family_b.to_string(),
        // A user id of another tenant, for the revoke-everything-for-a-user probe.
        UserId::generate(&env, &scope_b).to_string(),
        absent_in_a,
    ];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // Neither victim was revoked by any probe: both still resolve in their own scope.
    for (scope, victim) in [(scope_b, &victim_b), (scope_a2, &victim_a2)] {
        assert!(
            db.store()
                .scoped(scope)
                .sessions()
                .get(victim, 0, 0)
                .await
                .expect("read")
                .is_some(),
            "a foreign session must survive every probe"
        );
    }
}

#[tokio::test]
async fn account_credential_surfaces_are_cross_tenant_and_cross_environment_isolated() {
    // The self-service credential removal (issue #61) must refuse a credential id
    // minted in another tenant or environment as the uniform not-found, never a
    // cross-scope deletion.
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    // Plant a victim credential in each foreign scope, keeping its owning subject so
    // the survival check can list it back.
    let (subject_b, victim_b) = plant_credential(&db, &env, scope_b).await;
    let (subject_a2, victim_a2) = plant_credential(&db, &env, scope_a2).await;

    let mut harness = IdorHarness::new();
    harness.register_account_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["account_credentials.remove"],
        "the account-credential surface is registered with the harness"
    );

    let foreign = [victim_b.clone(), victim_a2.clone()];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // Neither victim credential was removed: both still list in their own scope.
    for (scope, subject, id) in [
        (scope_b, subject_b, victim_b),
        (scope_a2, subject_a2, victim_a2),
    ] {
        let listed = db
            .store()
            .scoped(scope)
            .account_credentials()
            .list(&subject, 50, None)
            .await
            .expect("list");
        assert!(
            listed.iter().any(|cred| cred.id == id),
            "a foreign credential must survive every probe"
        );
    }
}

#[tokio::test]
async fn connector_surfaces_are_cross_tenant_and_cross_environment_isolated() {
    // A federation connector (issue #75) registered in another tenant or environment
    // must be the uniform not-found on both the read and the delete surface, never a
    // cross-scope read or removal. Run on the CONTROL store, the plane that owns the
    // connector lifecycle (it holds the delete grant).
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = plant_connector(&db, &env, scope_b).await;
    let victim_a2 = plant_connector(&db, &env, scope_a2).await;

    let mut harness = IdorHarness::new();
    harness.register_connector_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["connectors.get", "connectors.delete"],
        "every connector surface is registered with the harness"
    );

    let foreign = [victim_b.clone(), victim_a2.clone()];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.control_store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // Neither victim connector was deleted: both still resolve in their own scope.
    for (scope, id) in [(scope_b, victim_b), (scope_a2, victim_a2)] {
        let parsed = ConnectorId::parse_in_scope(&id, &scope).expect("id parses in its own scope");
        db.control_store()
            .scoped(scope)
            .connectors()
            .get(&parsed)
            .await
            .expect("a foreign connector must survive every probe");
    }
}

#[tokio::test]
async fn federation_login_state_consume_is_cross_scope_isolated() {
    // A federation correlation row (issue #75, PR B) planted in another tenant or environment
    // must never be CONSUMED under the caller's scope, or a callback could burn a foreign
    // tenant's pending federated login (and recover its sealed PKCE verifier). The probe's
    // foreign identifier is the row's opaque STATE (the natural consume key). Run on the DATA
    // store (ironauth_app), which owns the correlation-store grants.
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = plant_federation_state(&db, &env, scope_b).await;
    let victim_a2 = plant_federation_state(&db, &env, scope_a2).await;

    let mut harness = IdorHarness::new();
    harness.register_federation_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["federation_login_states.consume"],
        "the federation correlation surface is registered with the harness"
    );

    let foreign = [victim_b.clone(), victim_a2.clone()];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // Each victim row is STILL consumable in its OWN scope (the cross-scope probe never
    // burned it), proving the isolation is a genuine scope boundary, not a global miss.
    for (scope, state) in [(scope_b, victim_b), (scope_a2, victim_a2)] {
        let consumed = db
            .store()
            .scoped(scope)
            .federation_login_states()
            .consume(&state, 1_000_000)
            .await
            .expect("consume in own scope")
            .expect("the row survives every cross-scope probe");
        assert_eq!(consumed.connector_id, "cnr_probe");
    }
}

/// Plant a federation correlation row in `scope` (provisioning the scope's envelope keys via
/// a connector first, since sealing the PKCE verifier needs a DEK) and return its `state`.
async fn plant_federation_state(db: &TestDatabase, env: &Env, scope: Scope) -> String {
    // Provision the scope's KEK/DEK (the connector create does this on the control plane).
    plant_connector(db, env, scope).await;
    let id = FederationLoginStateId::generate(env, &scope);
    let state = format!("state-{id}");
    db.store()
        .scoped(scope)
        .federation_login_states()
        .create(
            env,
            &id,
            NewFederationLoginState {
                state: &state,
                nonce: "nonce-probe",
                code_verifier: b"verifier-probe",
                connector_id: "cnr_probe",
                return_to: "/authorize?client_id=probe",
                org_connection_id: None,
                link_target_user_id: None,
                expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("plant federation login state");
    state
}

/// Plant a federation connector in `scope` and return its id string.
async fn plant_connector(db: &TestDatabase, env: &Env, scope: Scope) -> String {
    let id = ConnectorId::generate(env, &scope);
    let definition = r#"{"connector_id":"probe","display_name":"Probe","protocol":"oidc","endpoints":{"issuer":"https://probe.example.com"},"scopes":["openid"],"client_id":"ic"}"#;
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .connectors()
        .create(
            env,
            &id,
            1_000_000,
            NewConnector {
                slug: "probe",
                definition_json: definition,
                client_secret: b"probe-secret",
                capabilities: ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "untrusted",
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("plant connector");
    id.to_string()
}

/// Plant a live account credential in `scope` and return its owning subject and id.
async fn plant_credential(db: &TestDatabase, env: &Env, scope: Scope) -> (UserId, String) {
    let subject = UserId::generate(env, &scope);
    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .account_credentials()
        .enroll(
            env,
            &subject,
            CredentialType::Passkey,
            "victim key",
            "probe",
        )
        .await
        .expect("plant credential");
    (subject, id.to_string())
}

/// Plant a live session in `scope` (with a far-future lifetime), for the fleet probes.
async fn plant_session(db: &TestDatabase, env: &Env, scope: Scope) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            NewSession {
                subject: &UserId::generate(env, &scope).to_string(),
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("plant session");
    id
}

/// Plant a live refresh family on `session` in `scope`, so the refresh-family fleet
/// probes have a foreign row of their OWN type to hunt for.
async fn plant_refresh_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    session: &SessionId,
) -> RefreshFamilyId {
    let subject = UserId::generate(env, &scope).to_string();
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    let session_text = session.to_string();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: &client_id,
                redirect_uri: "https://client.test/cb",
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject: &subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: Some(&session_text),
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("plant grant");

    let family_id = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &digest,
                grant_id: &grant_id,
                subject: &subject,
                client_id: "cli_family",
                scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline: false,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("plant refresh family");
    family_id
}

#[tokio::test]
async fn upstream_token_read_is_cross_scope_isolated() {
    // A session's captured upstream tokens (issue #77, PR 3) planted in another tenant or
    // environment must never resolve under the caller's scope, or a retrieval could
    // exfiltrate a foreign tenant's upstream access and refresh tokens. The probe's foreign
    // identifier is the SESSION id (the vault's read key). Run on the DATA store
    // (ironauth_app), which carries the platform master key the seal path needs.
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = plant_upstream_token(&db, &env, scope_b).await;
    let victim_a2 = plant_upstream_token(&db, &env, scope_a2).await;

    let mut harness = IdorHarness::new();
    harness.register_upstream_token_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["upstream_tokens.read_for_session"],
        "the upstream token vault surface is registered with the harness"
    );

    let foreign = [victim_b.to_string(), victim_a2.to_string()];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // Each victim's token is STILL readable in its OWN scope (the cross-scope probe never
    // touched it), proving the isolation is a genuine scope boundary, not a global miss.
    for (scope, session) in [(scope_b, &victim_b), (scope_a2, &victim_a2)] {
        let material = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .upstream_tokens()
            .read_for_session(&env, session, UPSTREAM_TOKEN_PROBE_CONNECTOR)
            .await
            .expect("read in own scope")
            .expect("the token survives every cross-scope probe");
        assert_eq!(
            material.access_token.open(),
            b"upstream-at",
            "the token round-trips in its own scope"
        );
    }
}

#[tokio::test]
async fn upstream_token_read_is_connector_filtered() {
    // LOW-1 coherence hardening (issue #77, PR 3): read_for_session filters on BOTH the
    // session AND the grant-authorized connector, so a client granted for one org
    // connection can never read a token that was captured while the SAME session was routed
    // through a DIFFERENT org connection sharing a connector under a different grant policy.
    // Construct the shared-connector case directly at the store: a token captured under one
    // connector is invisible to a read scoped to a different connector, and visible only to
    // a read scoped to the connector it was captured under. Run on the DATA store
    // (ironauth_app), which carries the platform master key the seal path needs.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The helper captures the token under UPSTREAM_TOKEN_PROBE_CONNECTOR.
    let session = plant_upstream_token(&db, &env, scope).await;

    // A read scoped to a DIFFERENT connector returns the uniform None: the coherence gap is
    // closed, because a grant authorizing a sibling org connection's connector reads no
    // token that was captured under another connector for this session.
    let mismatched = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .upstream_tokens()
        .read_for_session(&env, &session, "cnr_other_connector")
        .await
        .expect("a connector mismatch is an infallible None, never an error");
    assert!(
        mismatched.is_none(),
        "a token captured under one connector must not resolve for a different connector"
    );

    // The SAME session's token IS readable under the connector it was captured under, so the
    // filter is a genuine connector boundary and not a blanket miss.
    let matched = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .upstream_tokens()
        .read_for_session(&env, &session, UPSTREAM_TOKEN_PROBE_CONNECTOR)
        .await
        .expect("read in own scope")
        .expect("the token resolves under the connector it was captured under");
    assert_eq!(
        matched.access_token.open(),
        b"upstream-at",
        "the token round-trips when the read connector matches the capture connector"
    );
}

/// Plant a captured upstream token keyed on a fresh session in `scope`, returning the
/// session id (the vault's read key).
async fn plant_upstream_token(db: &TestDatabase, env: &Env, scope: Scope) -> SessionId {
    let session = plant_session(db, env, scope).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .upstream_tokens()
        .capture(
            env,
            &UpstreamTokenId::generate(env, &scope),
            1_000_000,
            NewUpstreamTokens {
                session_id: &session,
                connector_id: UPSTREAM_TOKEN_PROBE_CONNECTOR,
                access_token: b"upstream-at",
                refresh_token: Some(b"upstream-rt"),
                access_expires_at_unix_micros: Some(FAR_FUTURE_MICROS),
                token_scope: "openid",
            },
        )
        .await
        .expect("capture upstream token");
    session
}
