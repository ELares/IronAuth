// SPDX-License-Identifier: MIT OR Apache-2.0

//! Carrying out a change set (issue #142).
//!
//! The other half of the dry-run contract. [`crate::ldap_changeset::ChangeSet`] is what a run
//! WOULD do; this performs exactly that value and nothing derived separately, which is what makes
//! "dry-run reports the exact change set a subsequent real run applies" a property of the code
//! rather than of two implementations agreeing.
//!
//! # The directory's identifier is the account's external id
//!
//! A run has to find the account it made for a directory principal last time. It keys on the
//! stable identifier -- `objectGUID`, `entryUUID`, or the DN where the server publishes neither
//! -- stored as the user's `external_id`, which is exactly what that column is for. Keying on the
//! login instead would mean a rename created a second person, and keying on the DN would mean a
//! move did.
//!
//! # Every operation is idempotent, because a pass repeats
//!
//! The sweep runs hourly and the previous snapshot may be stale, lost, or empty. So provisioning
//! somebody who already exists is a no-op rather than a conflict, and removing somebody already
//! gone is a no-op rather than an error. Without that, one interrupted run leaves every later run
//! failing on the same rows.
//!
//! # One failure does not abandon the rest
//!
//! The same reasoning as the sweep's per-connector isolation, one level down: a change that fails
//! is recorded against its principal and the run continues. A single unwritable row must not
//! leave the other ninety-nine unapplied and undiagnosed.

use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, NewAdminUser, OffboardingSchedule, Scope, Store, StoreError, UserState,
};

use crate::ldap_changeset::{Change, ChangeSet};

/// What a run actually did.
#[derive(Debug, Default, Clone)]
pub struct ExecuteReport {
    /// Accounts created.
    pub provisioned: usize,
    /// Arrivals that already had an account, so nothing was created.
    pub already_present: usize,
    /// Accounts moved out of a state that can authenticate.
    pub deactivated: usize,
    /// Accounts removed.
    pub deleted: usize,
    /// Removals for a principal with no account, so nothing was removed.
    pub already_absent: usize,
    /// Per-principal failures. The run continued past each of these.
    pub failures: Vec<(String, String)>,
}

impl ExecuteReport {
    /// Whether every change was carried out.
    #[must_use]
    pub fn everything_applied(&self) -> bool {
        self.failures.is_empty()
    }

    /// Fold another run's counts into this one.
    ///
    /// ONE PLACE, because a pass sums these at two levels (per connector, then per scope) and two
    /// hand-written sums over six fields is how one of them silently loses a field.
    pub fn absorb(&mut self, other: Self) {
        self.provisioned += other.provisioned;
        self.already_present += other.already_present;
        self.deactivated += other.deactivated;
        self.deleted += other.deleted;
        self.already_absent += other.already_absent;
        self.failures.extend(other.failures);
    }

    /// How many accounts this run actually changed.
    ///
    /// Excludes the no-ops deliberately: a pass over an unchanged directory should report zero,
    /// not the size of the directory, or a quiet run and a churning one look the same in a log.
    #[must_use]
    pub fn changed(&self) -> usize {
        self.provisioned + self.deactivated + self.deleted
    }
}

/// Carry out a change set.
///
/// Never returns early: a failed change is recorded and the run continues.
pub async fn execute(
    store: &Store,
    scope: Scope,
    env: &Env,
    actor: ActorRef,
    changes: &ChangeSet,
) -> ExecuteReport {
    let mut report = ExecuteReport::default();
    for change in &changes.changes {
        let stable_id = match change {
            Change::Provision { stable_id, .. }
            | Change::Deactivate { stable_id }
            | Change::Delete { stable_id } => stable_id.clone(),
        };
        if let Err(error) = apply_one(store, scope, env, actor, change, &mut report).await {
            report.failures.push((stable_id, error.to_string()));
        }
    }
    report
}

/// One change, with the lookup that makes it idempotent.
async fn apply_one(
    store: &Store,
    scope: Scope,
    env: &Env,
    actor: ActorRef,
    change: &Change,
    report: &mut ExecuteReport,
) -> Result<(), StoreError> {
    match change {
        Change::Provision {
            stable_id,
            username,
        } => {
            if store
                .scoped(scope)
                .users()
                .by_external_id(stable_id)
                .await?
                .is_some()
            {
                report.already_present += 1;
                return Ok(());
            }
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(env))
                .users()
                .admin_create(
                    env,
                    NewAdminUser {
                        id: None,
                        identifier: username,
                        // NO CREDENTIAL. A directory account authenticates through the directory,
                        // and minting a password here would create one nobody set and nobody
                        // rotates. The login fence refuses a credential-less account until one
                        // exists, which is the correct posture for a synced identity.
                        password_hash: None,
                        claims_json: None,
                        // THE LINK, AT CREATION. Done here rather than as a second call so a
                        // crash between the two cannot leave an account the next pass cannot
                        // find -- which would provision a duplicate every hour, for ever.
                        external_id: Some(stable_id),
                        state: UserState::Active,
                        foreign_password_hash: None,
                        foreign_password_algo: None,
                        traits: None,
                    },
                    now_micros(env),
                    None,
                )
                .await?;
            report.provisioned += 1;
            Ok(())
        }
        Change::Deactivate { stable_id } => {
            let Some(existing) = store
                .scoped(scope)
                .users()
                .by_external_id(stable_id)
                .await?
            else {
                report.already_absent += 1;
                return Ok(());
            };
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(env))
                .users()
                .set_state(
                    env,
                    &existing.id,
                    // DISABLED rather than BLOCKED. Both stop authentication and end live
                    // sessions; the store's own doc says the difference is that the operator's
                    // intent is legible. Somebody who left the directory was not blocked by an
                    // administrator, and reading it back as if they were would misattribute the
                    // decision.
                    UserState::Disabled,
                    OffboardingSchedule {
                        at_unix_micros: None,
                        wake_payload: None,
                    },
                    // HARD KILL. The person is gone from the directory; leaving their sessions
                    // alive until expiry is the window this whole subsystem exists to close.
                    true,
                    None,
                )
                .await?;
            report.deactivated += 1;
            Ok(())
        }
        Change::Delete { stable_id } => {
            let Some(existing) = store
                .scoped(scope)
                .users()
                .by_external_id(stable_id)
                .await?
            else {
                report.already_absent += 1;
                return Ok(());
            };
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(env))
                .users()
                .delete(env, &existing.id, true, None, None)
                .await?;
            report.deleted += 1;
            Ok(())
        }
    }
}

/// The clock, read through `Env` like everything else timed here.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}

/// Work out what a run would do, then do it.
///
/// THE WHOLE POINT OF THE SPLIT, in one function: the value printed by a dry run and the value
/// executed by a real run are the same value, produced once. A caller that wants the dry run
/// calls [`ChangeSet::from_plan`] and stops.
pub async fn plan_and_execute(
    store: &Store,
    scope: Scope,
    env: &Env,
    actor: ActorRef,
    plan: &crate::ldap_sync::SyncPlan,
    policy: ironauth_store::LdapAbsencePolicy,
) -> (ChangeSet, ExecuteReport) {
    let changes = ChangeSet::from_plan(plan, policy);
    let report = execute(store, scope, env, actor, &changes).await;
    (changes, report)
}
