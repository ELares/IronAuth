// SPDX-License-Identifier: MIT OR Apache-2.0

//! The rotation timer: the durable driver for the state machine (issue #160).
//!
//! # The timer, and why it needs no leader lease
//!
//! The runner's pass is IDEMPOTENT by construction: the machine's transitions fire
//! only when their instant has arrived, the promotion retires exactly the previous
//! head, and the withdrawal audit is idempotent. Two nodes advancing the same
//! environment at the same instant therefore converge, and a crashed node's next
//! pass simply re-takes what it missed. That is the HA story the issue's "single
//! execution under HA via the existing coordination primitives" asks for: the
//! coordination primitive is the machine's own idempotence, applied to the real
//! clock.
//!
//! The pass iterates EVERY environment in the database. A per-environment issuer is
//! isolated by its scope, and the machine mints every successor under its own scope,
//! so the two-environments-never-share-keys property holds across the whole pass.
//!
//! The enumeration rides the CONTROL store: `environments` is only readable by the
//! control role (FORCE RLS, unscoped reads impossible), and every other
//! scope-enumerating worker in the product uses the control DSN for exactly this. The
//! machine's transitions ride the APP store, whose column-scoped lifecycle grants are
//! the ones the handoff UPDATE needs.

use crate::key_rotation::{RotationPolicy, RotationStateMachine};
use crate::{ActorRef, CorrelationId, Store, StoreError};
use ironauth_env::Env;
use std::time::Duration;

/// The rotation timer: one pass over every environment, then sleep, repeat.
pub struct RotationTimer {
    app_store: Store,
    control_store: Store,
    policy: RotationPolicy,
    max_token_lifetime_secs: u64,
    interval: Duration,
    /// The remote-key seeding (issue #161): the provisioner a remote deployment's
    /// machine asks before storing a REMOTE-REFERENCE successor. `None` for the
    /// local key store.
    provisioner: Option<Box<dyn crate::key_rotation::RemoteKeyProvisioner>>,
}

impl RotationTimer {
    /// A timer for `store` with the operator's policy.
    #[must_use]
    pub fn new(
        app_store: Store,
        control_store: Store,
        policy: RotationPolicy,
        max_token_lifetime_secs: u64,
        interval: Duration,
    ) -> Self {
        Self {
            app_store,
            control_store,
            policy,
            max_token_lifetime_secs,
            interval,
            provisioner: None,
        }
    }

    /// Arm remote-key seeding (issue #161): the timer's machine then stores
    /// REMOTE references and asks `provisioner` to confirm each key before
    /// storing it.
    #[must_use]
    pub fn with_remote_seeding(
        mut self,
        provisioner: Box<dyn crate::key_rotation::RemoteKeyProvisioner>,
    ) -> Self {
        self.provisioner = Some(provisioner);
        self
    }

    /// The pass loop. Runs until the task is cancelled; a failed pass is logged and
    /// the interval continues (a persistent failure never wedges the loop).
    pub async fn run(&self, env: &Env) {
        loop {
            if let Err(error) = self.pass(env).await {
                tracing::error!("signing-key rotation pass failed: {error}");
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    /// One pass: advance the machine for every environment in the database.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure; a failed pass changes
    /// nothing for the environment it failed on, and the next pass converges.
    pub async fn pass(&self, env: &Env) -> Result<(), StoreError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT tenant_id, id FROM environments ORDER BY tenant_id, id")
                .fetch_all(self.control_store.pool())
                .await?;
        let now_micros = now_micros(env);
        for (tenant, environment) in rows {
            let Ok(tenant) = crate::TenantId::parse(&tenant) else {
                continue;
            };
            let Ok(environment) = crate::EnvironmentId::parse(&environment) else {
                continue;
            };
            let scope = crate::Scope::new(tenant, environment);
            let mut machine = RotationStateMachine::new(
                &self.app_store,
                scope,
                ActorRef::agent(crate::AgentId::generate(env)),
                CorrelationId::generate(env),
            );
            if let Some(provisioner) = self.provisioner.as_deref() {
                machine = machine.with_remote_seeding(provisioner);
            }
            let report = machine
                .advance(env, self.policy, now_micros, self.max_token_lifetime_secs)
                .await?;
            if !report.provisioned.is_empty()
                || !report.promoted.is_empty()
                || !report.retired.is_empty()
            {
                tracing::info!(
                    tenant = %scope.tenant(),
                    environment = %scope.environment(),
                    provisioned = report.provisioned.len(),
                    promoted = report.promoted.len(),
                    retired = report.retired.len(),
                    "signing-key rotation pass advanced an environment"
                );
            }
        }
        Ok(())
    }
}

/// The clock seam's now, in epoch microseconds.
fn now_micros(env: &Env) -> i64 {
    crate::repository::epoch_micros_public(env.clock().now_utc())
}
