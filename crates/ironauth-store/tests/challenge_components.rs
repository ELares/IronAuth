// SPDX-License-Identifier: MIT OR Apache-2.0

//! Custom factor components over a real database (issue #114 criterion 6).
//!
//! The table a journey step references by name, and the grants that decide what a factor may
//! read. What is proved here:
//!
//! - **The grant split the migration draws.** The control plane deploys, the data plane READS
//!   and cannot write. A factor is code that decides whether a login succeeds, so the plane that
//!   runs one must not be the plane that can change it.
//! - **Cross-scope isolation**, which is the RLS policy doing its job rather than a filter in a
//!   query: the reads below name no tenant, so a component leaking across scopes would leak
//!   through the policy.
//! - **The CASCADE**, which is what makes a grant impossible to orphan. A grant that outlived
//!   its component would be re-attached silently by a later deploy of the same name -- a
//!   capability nobody granted -- and that is the failure this file exists to make impossible.
//! - **The bounds the table carries**, refused at the write rather than discovered at a login.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ChallengeDeployment, CorrelationId, StoreError};

/// Eight bytes of WebAssembly component preamble: enough to be a non-empty artifact, which is
/// all this layer checks. Whether it EXPORTS the triad is decided where it is loaded, by
/// wasmtime, and a store test that shipped a real component would be testing the compiler.
const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

fn deployment(name: &str) -> ChallengeDeployment<'_> {
    ChallengeDeployment {
        name,
        component: COMPONENT,
        payload_version: 1,
        fetch_budget: 0,
        aot: None,
    }
}

#[tokio::test]
async fn a_component_deployed_on_the_control_plane_is_read_by_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("deploy");

    // THE DATA PLANE, which is the plane the login path runs on. Reading it back on the control
    // plane would prove the write and nothing about whether a login can reach it.
    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the deployed component");
    assert_eq!(record.name, "wordmark");
    assert_eq!(record.component, COMPONENT);
    assert_eq!(record.payload_version, 1);
    assert_eq!(
        record.fetch_budget, 0,
        "absent means NOT GRANTED, and the record says so rather than leaving it to a default \
         somewhere else"
    );
    assert!(
        record.granted_secrets.is_empty(),
        "a component nobody granted anything to reads nothing"
    );
}

/// A REDEPLOY REPLACES THE CODE AND APPLIES THE BUDGET, KEYED ON THE NAME.
///
/// The name is the journey's reference, so replacing in place under one name is how a factor is
/// updated without touching the journeys that use it. The budget travels with the code for the
/// reason a token hook's does: shipping a version that no longer calls out must not leave the
/// grant standing.
#[tokio::test]
async fn a_redeploy_replaces_the_code_and_applies_the_budget() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let acting = || {
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    acting()
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("first deploy");

    let mut longer = COMPONENT.to_vec();
    longer.push(0x00);
    acting()
        .challenge_components()
        .deploy(
            &env,
            ChallengeDeployment {
                name: "wordmark",
                component: &longer,
                payload_version: 1,
                fetch_budget: 3,
                aot: None,
            },
            None,
        )
        .await
        .expect("redeploy");

    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the component");
    assert_eq!(record.component, longer, "the code was replaced in place");
    assert_eq!(record.fetch_budget, 3, "and the grant was applied");

    let listed = db
        .store()
        .scoped(scope)
        .challenge_components()
        .list()
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "a redeploy under an existing name REPLACES rather than adding a second row: two rows \
         would mean a journey reference no longer names one component"
    );
}

/// A GRANT NAMES A SECRET, AND DELETING THE COMPONENT TAKES IT WITH IT.
///
/// The CASCADE is the point. A grant that outlived its component would be silently re-attached
/// by a later deploy of the same name, and that is a capability nobody granted -- the second
/// half of this test is what makes that impossible rather than merely unlikely.
#[tokio::test]
async fn a_grant_is_cascaded_away_with_its_component() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let acting = || {
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    acting()
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("deploy");
    acting()
        .challenge_components()
        .grant_secret(&env, "wordmark", "wordmark_list", None)
        .await
        .expect("grant");

    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the component");
    assert_eq!(
        record.granted_secrets,
        vec!["wordmark_list".to_owned()],
        "the grant reaches the record the login path reads, in the SAME query as the component"
    );

    acting()
        .challenge_components()
        .delete(&env, "wordmark", None)
        .await
        .expect("delete");

    // REDEPLOY THE SAME NAME. If the grant had survived, this component would hold a capability
    // nobody granted it.
    acting()
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("redeploy after delete");
    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the component");
    assert!(
        record.granted_secrets.is_empty(),
        "a component redeployed under a deleted name must start ungranted: the CASCADE is what \
         makes the grant impossible to inherit, and without it this is a silent privilege \
         escalation across a delete"
    );
}

/// A GRANT TO A COMPONENT THAT IS NOT DEPLOYED IS A NOT-FOUND.
///
/// Refused rather than stored, because a grant waiting for a name is a capability waiting for
/// whoever deploys it next. The foreign key would refuse it too, but a constraint violation
/// reaches an operator as a 500 while this reaches them as a not-found.
#[tokio::test]
async fn a_grant_to_an_undeployed_component_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let error = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .grant_secret(&env, "never-deployed", "wordmark_list", None)
        .await
        .expect_err("a grant to a component that does not exist must be refused");
    assert!(
        matches!(error, StoreError::NotFound),
        "and refused as a not-found rather than a constraint violation: {error:?}"
    );
}

/// A REVOKE IS IDEMPOTENT AND A DELETE IS NOT.
///
/// The asymmetry is deliberate and worth pinning. Revoking a name that was never granted leaves
/// the component unable to read it, which is what the caller asked for, so a cleanup script that
/// runs twice must not fail. Deleting a component that does not exist is a different claim --
/// reporting success would tell an operator their removal took effect and would turn the
/// endpoint into a probe for which factors a tenant runs.
#[tokio::test]
async fn a_revoke_is_idempotent_and_a_delete_of_nothing_is_not() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let acting = || {
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    acting()
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("deploy");
    for round in 1..=2 {
        acting()
            .challenge_components()
            .revoke_secret(&env, "wordmark", "never-granted", None)
            .await
            .unwrap_or_else(|error| panic!("revoke round {round} must succeed: {error:?}"));
    }

    let error = acting()
        .challenge_components()
        .delete(&env, "never-deployed", None)
        .await
        .expect_err("deleting nothing is not success");
    assert!(
        matches!(error, StoreError::NotFound),
        "a delete that matched nothing is a not-found: {error:?}"
    );
}

/// THE DATA PLANE CANNOT DEPLOY.
///
/// The grant split, asserted from the side that would be a privilege escalation. The data plane
/// runs factors; if it could also write one, a compromise of the login path would be a compromise
/// of what the login path decides.
#[tokio::test]
async fn the_data_plane_cannot_write_a_component() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let error = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect_err("the data plane must not be able to deploy a factor");
    assert!(
        matches!(error, StoreError::Database(_)),
        "Postgres refuses it before any application logic runs: {error:?}"
    );
}

/// A COMPONENT NEVER LEAVES ITS SCOPE.
///
/// The read below names no tenant: it is scoped by the connection setting the RLS policy reads,
/// so a component visible in the wrong scope would be the policy failing rather than a query
/// missing a filter.
#[tokio::test]
async fn a_component_is_invisible_outside_its_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let first = db.seed_scope(&env).await;
    let second = db.seed_scope(&env).await;

    db.control_store()
        .scoped(first)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("deploy in the first scope");

    assert!(
        db.store()
            .scoped(second)
            .challenge_components()
            .get("wordmark")
            .await
            .expect("read")
            .is_none(),
        "the other scope must not see it"
    );
    assert!(
        db.store()
            .scoped(second)
            .challenge_components()
            .list()
            .await
            .expect("list")
            .is_empty(),
        "and it must not appear in the other scope's listing either -- the listing is the read \
         an operator uses to audit which factors run, so a leak here is a leak of what another \
         tenant has deployed"
    );
}

/// THE TABLE'S OWN BOUNDS ARE ENFORCED AT THE WRITE.
///
/// Each of these is refused by a CHECK rather than by the admin path alone, which is what makes
/// them true of every writer rather than of the one that happens to validate.
#[tokio::test]
async fn the_bounds_are_refused_at_the_write() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let acting = || {
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    let cases: [(&str, ChallengeDeployment<'_>); 4] = [
        (
            "an empty component is not a component",
            ChallengeDeployment {
                name: "empty",
                component: &[],
                payload_version: 1,
                fetch_budget: 0,
                aot: None,
            },
        ),
        (
            "an empty name is not a journey reference",
            ChallengeDeployment {
                name: "",
                component: COMPONENT,
                payload_version: 1,
                fetch_budget: 0,
                aot: None,
            },
        ),
        (
            "an unknown payload version is one no invocation could honour",
            ChallengeDeployment {
                name: "future",
                component: COMPONENT,
                payload_version: 2,
                fetch_budget: 0,
                aot: None,
            },
        ),
        (
            "a budget past the ceiling is refused by the column, not only by the door",
            ChallengeDeployment {
                name: "greedy",
                component: COMPONENT,
                payload_version: 1,
                fetch_budget: 17,
                aot: None,
            },
        ),
    ];

    for (why, deployment) in cases {
        let error = acting()
            .challenge_components()
            .deploy(&env, deployment, None)
            .await
            .expect_err(why);
        assert!(matches!(error, StoreError::Database(_)), "{why}: {error:?}");
    }
}

/// AN ARTIFACT IS STORED WITH THE COMPONENT AND READ BACK WITH IT (issue #114 criterion 4).
///
/// The pairing is the point: the record carries both or neither, and the key is what a caller
/// compares before deciding to execute machine code. A store that returned the artifact without
/// the key would hand a caller something it cannot make that decision about.
#[tokio::test]
async fn an_artifact_and_its_key_travel_together() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let aot = ironauth_store::AotArtifact {
        artifact: vec![0xde, 0xad, 0xbe, 0xef],
        engine_key: "a".repeat(64),
    };

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(
            &env,
            ChallengeDeployment {
                aot: Some(&aot),
                ..deployment("wordmark")
            },
            None,
        )
        .await
        .expect("deploy with an artifact");

    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the component");
    let stored = record.aot.expect("the artifact reaches the login path");
    assert_eq!(stored.artifact, aot.artifact);
    assert_eq!(
        stored.engine_key, aot.engine_key,
        "the KEY comes back with it, or a caller cannot decide whether to execute the bytes"
    );
}

/// A REDEPLOY WITHOUT AN ARTIFACT CLEARS THE ONE THAT WAS THERE.
///
/// The dangerous direction. An artifact left behind by a previous deploy is machine code for a
/// component that is no longer in the row -- and because the KEY would still match this build, it
/// would load, and the code that ran would be the old one. A stale artifact is worse than none.
#[tokio::test]
async fn a_redeploy_without_an_artifact_clears_the_stale_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let acting = || {
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let aot = ironauth_store::AotArtifact {
        artifact: vec![0xde, 0xad, 0xbe, 0xef],
        engine_key: "b".repeat(64),
    };

    acting()
        .challenge_components()
        .deploy(
            &env,
            ChallengeDeployment {
                aot: Some(&aot),
                ..deployment("wordmark")
            },
            None,
        )
        .await
        .expect("deploy with an artifact");

    // A second deploy of DIFFERENT bytes, by a caller with no engine.
    let mut longer = COMPONENT.to_vec();
    longer.push(0x00);
    acting()
        .challenge_components()
        .deploy(
            &env,
            ChallengeDeployment {
                name: "wordmark",
                component: &longer,
                payload_version: 1,
                fetch_budget: 0,
                aot: None,
            },
            None,
        )
        .await
        .expect("redeploy without one");

    let record = db
        .store()
        .scoped(scope)
        .challenge_components()
        .get("wordmark")
        .await
        .expect("read")
        .expect("the component");
    assert_eq!(record.component, longer, "the new code is stored");
    assert!(
        record.aot.is_none(),
        "and the stale artifact is GONE: its key would still match this build, so leaving it \
         would mean the next login loaded machine code for the component that was just replaced"
    );
}

/// THE COLUMN REFUSES A HALF-POPULATED ROW AND A MALFORMED KEY.
///
/// The `both or neither` CHECK is what lets the read return a type that cannot express one half.
/// The key's SHAPE is checked because it gates an unsafe load through a string comparison: a
/// column admitting an empty or truncated digest would make "the keys matched" weaker than it
/// reads.
#[tokio::test]
async fn the_artifact_columns_refuse_a_half_row_and_a_malformed_key() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(&env, deployment("wordmark"), None)
        .await
        .expect("deploy");

    // Written through the OWNER pool, because the point is the CHECK rather than the repository:
    // the repository's type makes these unrepresentable, and the constraint is what holds for
    // any other writer.
    let pool = db.owner_pool();
    for (artifact, key, why) in [
        (
            Some(vec![0x00_u8]),
            None,
            "an artifact with no key cannot be checked",
        ),
        (
            None,
            Some("c".repeat(64)),
            "a key with no artifact describes nothing",
        ),
        (
            Some(vec![0x00_u8]),
            Some("short".to_owned()),
            "a truncated digest is not a key",
        ),
        (
            Some(vec![0x00_u8]),
            Some("Z".repeat(64)),
            "a non-hex key is not one this build could have written",
        ),
    ] {
        let result = sqlx::query(
            "UPDATE challenge_components SET aot_artifact = $1, aot_engine_key = $2 \
             WHERE tenant_id = $3 AND environment_id = $4 AND name = 'wordmark'",
        )
        .bind(artifact)
        .bind(key)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(pool)
        .await;
        assert!(result.is_err(), "{why}");
    }
}
