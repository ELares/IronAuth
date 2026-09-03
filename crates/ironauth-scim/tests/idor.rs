// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM half of the cross-scope IDOR harness (issue #135, criterion 5).
//!
//! # Why this exists separately from the surface tests
//!
//! `tests/users.rs`, `tests/groups.rs` and `tests/bulk.rs` drive the criterion's own words
//! through the real router: "a valid token for org A cannot read, create, or mutate any resource
//! in org B via any encoding, path traversal, filter, or bulk trick". Those are SURFACE
//! questions, and they are answered where the surface is.
//!
//! This file answers the layer beneath, and the distinction is not bookkeeping. `authenticate`
//! derives the scope FROM THE CREDENTIAL, so a surface test structurally cannot present a
//! foreign identifier under a caller's own scope -- the one thing it cannot construct is the one
//! thing a future handler that took an id from a request path would hand the store. The harness
//! constructs exactly that, for every SCIM repository operation that resolves a resource by
//! identifier.
//!
//! The criterion says the harness is "extended with SCIM-specific cases"; before this the word
//! SCIM did not appear in any `idor.rs` in the workspace.
//!
//! Needs a database.

use ironauth_env::Env;
use ironauth_store::identifier::{IdentifierType, UniquenessMode};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, EnterpriseWrite, NewAdminUser, NewMembership, NewScimConnection,
    NewUserIdentifier, OrgMembershipId, OrganizationId, ScimConnectionId, Scope, UserId,
    UserIdentifierId, UserState,
};

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// A victim organization with one provisioned person, everything a SCIM run would leave behind.
///
/// PLANTED IN FULL, because a read against an EMPTY scope proves nothing: every operation
/// answers not-found for a person who does not exist, whatever the fence does. Each read here
/// has a real row to leak.
///
/// SIX ROWS FOR FIVE READS. The login identifier and the organization membership are read by
/// nothing in this file and are not foreign-key prerequisites -- `scim_membership_activation`
/// references only `tenants` and `environments`. They are here because a victim with a
/// provisioning document and no membership is not a person any SCIM run would have produced,
/// and a fixture that could not have arisen is a fixture whose absences prove less than they
/// look like they do. An earlier version of this sentence said "one row for every probe", which
/// a review counted and found false.
///
/// THE THREE SCIM TABLES ARE PLANTED THROUGH THE DATA-PLANE STORE, because that is the plane
/// that owns them: 0184, 0185 and 0187 all grant INSERT to `ironauth_app` and give the control
/// plane a bare SELECT, on the argument that a mapping is written when an identity provider
/// provisions somebody rather than when an operator acts. Planting them as the control role
/// fails with 42501, which is the grant working.
struct Victim {
    organization: OrganizationId,
    user: UserId,
    connection: ScimConnectionId,
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture per probe; splitting it would separate a \
     planted row from the probe that reads it"
)]
async fn plant_victim(db: &TestDatabase, env: &Env, scope: Scope) -> Victim {
    let acting = db
        .control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let organization = OrganizationId::generate(env, &scope);
    acting
        .organizations(scope)
        .create(env, &organization, now_micros(env), "Victim", None)
        .await
        .expect("create the victim organization");

    let user = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier: "victim@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the victim person");

    // A login identifier, a membership, a provisioning connection, an externalId mapping, a
    // deactivation and an Enterprise User document: one row for every probe.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .user_identifiers()
        .add(
            env,
            NewUserIdentifier {
                id: &UserIdentifierId::generate(env, &scope),
                user_id: &user,
                identifier_type: IdentifierType::Email,
                raw: "victim@example.test",
                verified: false,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("plant the identifier");

    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id: &OrgMembershipId::generate(env, &scope),
                organization_id: &organization,
                user_id: &user,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("plant the membership");

    let connection = ScimConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .create(
            env,
            NewScimConnection {
                id: &connection,
                organization_id: &organization,
                display_name: "victim connection",
                provider: "okta",
                // A REAL digest shape: migration 0183 CHECKs it, and the constraint is what
                // stops a hand-written test planting something the surface could never store.
                token_digest: &ironauth_scim::server::digest_of(
                    &ironauth_scim::server::mint_token(&connection, "victim-secret"),
                ),
                expires_at_unix_micros: None,
            },
            None,
        )
        .await
        .expect("plant the connection");

    db.store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ironauth_store::ScimExternalIdId::generate(env, &scope),
            &connection,
            "victim-external-id",
            &user,
        )
        .await
        .expect("plant the external id");

    db.store()
        .scoped(scope)
        .scim_activation()
        .set_active(&organization, &user, false, now_micros(env))
        .await
        .expect("plant the deactivation");

    db.store()
        .scoped(scope)
        .scim_enterprise()
        .write(
            env,
            &organization,
            &user,
            &serde_json::json!({ "employeeNumber": "VICTIM-701" }),
            EnterpriseWrite::Replace,
            now_micros(env),
        )
        .await
        .expect("plant the enterprise attributes");

    Victim {
        organization,
        user,
        connection,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the cross-scope run and the can-it-see-a-row control \
     have to share one fixture, or the control proves nothing about the run"
)]
#[tokio::test]
async fn no_scim_repository_operation_resolves_a_foreign_identifier() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // The caller, and TWO victims: another tenant, and another environment of the caller's OWN
    // tenant. The second is the one a scope check written as a tenant comparison would miss.
    let caller = db.seed_scope(&env).await;
    let other_tenant = db.seed_scope(&env).await;
    let other_environment = Scope::new(
        caller.tenant(),
        db.seed_environment(&env, caller.tenant()).await,
    );

    let victim_tenant = plant_victim(&db, &env, other_tenant).await;
    let victim_environment = plant_victim(&db, &env, other_environment).await;

    // And a pair of the CALLER's own scope naming nothing, so the suite covers the ABSENT case
    // with the same reads: a fence that answered differently for "foreign" and "absent" would
    // tell a caller which scopes exist. Both halves are generated, because a read that resolves
    // on two identifiers needs two -- an earlier version passed a `usr_` id to a probe that
    // parsed it as an organization, so it was rejected as MALFORMED and never reached the
    // absent case at all.
    let absent_org = OrganizationId::generate(&env, &caller);
    let absent_user = UserId::generate(&env, &caller);

    // NOTHING IS REGISTERED IN THE HARNESS FOR SCIM, and that is a measurement rather than an
    // omission. An `IsolationProbe` receives one identifier and must parse it first, and for a
    // scope-EMBEDDING id `parse_in_scope` IS the scope check -- so a foreign id is refused
    // there and the operation is never reached. A review planted an assert inside
    // `list_for_organization` and it never fired for any id the probe was fed: the probe tested
    // the parser, which `OrganizationGetProbe` already tests.
    //
    // `ironauth-store/tests/scim_connections.rs` drives that one directly with a foreign
    // organization. Everything below drives the two-key operations the same way.

    // THE SINGLE-KEY LISTING, driven directly for the reason above.
    for organization in [
        &victim_tenant.organization,
        &victim_environment.organization,
    ] {
        assert!(
            db.store()
                .scoped(caller)
                .scim_connections()
                .list_for_organization(organization, 100, None)
                .await
                .unwrap_or_default()
                .is_empty(),
            "a foreign organization's provisioning connections were listable"
        );
    }

    // AND THE ABSENT PAIR, which must answer exactly as the foreign ones do: a fence that told
    // "foreign" from "absent" would tell a caller which scopes exist.
    assert!(
        db.store()
            .scoped(caller)
            .scim_enterprise()
            .document_for(&absent_org, &absent_user)
            .await
            .expect("an in-scope pair naming nothing is a clean read")
            .is_none(),
        "an absent in-scope pair must read as absent"
    );

    // THE TWO-KEY OPERATIONS, driven with BOTH identifiers foreign, which is the only shape
    // that names a real row in the victim's scope. Each is asked for the victim's exact pair
    // from the caller's scope.
    for victim in [&victim_tenant, &victim_environment] {
        let scoped = db.store().scoped(caller);
        assert!(
            scoped
                .scim_enterprise()
                .document_for(&victim.organization, &victim.user)
                .await
                .unwrap_or(None)
                .is_none(),
            "a foreign organization's Enterprise attributes were readable"
        );
        assert!(
            scoped
                .scim_external_ids()
                .external_id_for(&victim.connection, &victim.user)
                .await
                .unwrap_or(None)
                .is_none(),
            "a foreign connection's externalId mapping was readable"
        );
        // ABSENT READS AS ACTIVE by design (migration 0185), so `true` is the not-found answer
        // and only an explicit `false` could have come from the victim's row -- which is what
        // `plant_victim` wrote.
        assert!(
            scoped
                .scim_activation()
                .is_active(&victim.organization, &victim.user)
                .await
                .unwrap_or(true),
            "a foreign organization's deactivation was observable"
        );
        // THE WRITE, which matters more than any read: planting attributes on somebody else's
        // person is a takeover of what their organization believes about them.
        let planted = serde_json::json!({ "employeeNumber": "planted-across-a-scope" });
        let _ = db
            .store()
            .scoped(caller)
            .scim_enterprise()
            .write(
                &env,
                &victim.organization,
                &victim.user,
                &planted,
                EnterpriseWrite::Replace,
                now_micros(&env),
            )
            .await;
    }

    // THE CONTROL, and this suite is worth nothing without it.
    //
    // Every one of these operations is fenced THREE times: a Rust scope check on both
    // identifiers before any query runs, the explicit `tenant_id`/`environment_id` predicates
    // in the query itself, and the row-level-security policy the scoped transaction binds.
    // Removing any one leaks nothing, because the other two hold -- measured, one at a time and
    // then two at a time. Only with all three gone does the read return the victim's row, which
    // is what proves this assertion can fail at all.
    //
    // So the refusals above are equally consistent with reads that cannot observe a row.
    //
    // What separates the two is asking for the CALLER's own rows, where there is no fence to
    // pass. Each read must then find what `plant_victim` wrote.
    let local = plant_victim(&db, &env, caller).await;
    let scoped = db.store().scoped(caller);
    assert!(
        scoped
            .scim_enterprise()
            .document_for(&local.organization, &local.user)
            .await
            .expect("read")
            .is_some(),
        "the Enterprise read cannot see a row it is entitled to, so its refusals above mean \
         nothing"
    );
    assert!(
        scoped
            .scim_external_ids()
            .external_id_for(&local.connection, &local.user)
            .await
            .expect("read")
            .is_some(),
        "the externalId read is blind"
    );
    assert!(
        !scoped
            .scim_activation()
            .is_active(&local.organization, &local.user)
            .await
            .expect("read"),
        "the activation read is blind: it cannot see the deactivation that was planted"
    );
    assert!(
        !db.store()
            .scoped(caller)
            .scim_connections()
            .list_for_organization(&local.organization, 100, None)
            .await
            .expect("read")
            .is_empty(),
        "the connection listing is blind"
    );

    // AND THE VICTIMS ARE UNTOUCHED. The write probe attempts a real write, so "denied" has to
    // mean "changed nothing" and not merely "answered an error". Read back in the victim's OWN
    // scope, which is the only place the answer is visible.
    for victim in [&victim_tenant, &victim_environment] {
        let document = db
            .control_store()
            .scoped(if victim.user.scope() == other_tenant {
                other_tenant
            } else {
                other_environment
            })
            .scim_enterprise()
            .document_for(&victim.organization, &victim.user)
            .await
            .expect("read the victim's document in its own scope")
            .expect("the victim still has one");
        assert_eq!(
            document["employeeNumber"].as_str(),
            Some("VICTIM-701"),
            "a cross-scope probe changed a victim's Enterprise attributes: {document}"
        );
    }
}
