// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning stored connector rows into a runnable sweep (issue #142).
//!
//! This is the seam between the database and the sans-IO chain. Everything below it
//! ([`crate::ldap_sync`], [`crate::ldap_groups`], [`crate::ldap_diff`]) is pure and testable
//! without a directory; everything above it is a ticker. This module is where a row becomes a
//! connection.
//!
//! # The bind password is never in the row
//!
//! `ldap_connectors.bind_secret_name` holds the NAME of an `environment_secrets` row, never the
//! password. Resolving it is the one privileged thing this module does, and it is why the factory
//! carries a store rather than a pre-built config: a config struct with the password already in
//! it would have to be built somewhere, and that somewhere would be a wider blast radius than a
//! single `open_value` at connect time.
//!
//! # A connector that will not open is not a connector with nobody in it
//!
//! Every failure here -- a secret that is missing, a scheme that disagrees with `tls_mode`, a
//! bind that is refused -- surfaces as an error from [`SourceFactory::open`], which
//! [`crate::ldap_schedule::sweep`] records as `Unreachable` against that connector and moves on.
//! What must never happen is a failure that renders as an empty directory, because an empty
//! directory is read as everybody having left.

use std::collections::{BTreeMap, BTreeSet};

use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_store::outbox::ScopeSource;
use ironauth_store::{
    ActorRef, LdapAbsencePolicy, LdapConnector, LdapTlsMode, Scope, ServiceId, Store, StoreError,
};

use crate::ldap_changeset::ChangeSet;
use crate::ldap_client::{Directory, DirectoryConfig, TlsMode};
use crate::ldap_execute::{ExecuteReport, execute};
use crate::ldap_schedule::{Outcome, Scheduled, SourceFactory, SweepReport};
use crate::ldap_sync::SyncInputs;

/// How long to wait for a directory to answer a connect.
///
/// `ldap3` applies this to the TCP connect and nothing after it, which is why the sweep carries
/// its own deadline as well: a directory that accepts the socket and never answers the bind is
/// not caught by this.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long ONE connector gets, open and read together.
///
/// The bound that actually holds. Two minutes is generous for a directory of any size the paging
/// handles, and short enough that one unresponsive server does not eat an hour's tick.
const PER_CONNECTOR_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// RFC 2696 page size for every connector's searches.
///
/// Not per-connector today: the column does not exist, and inventing one here would be a setting
/// with no source. 500 is what the directories in this space default to.
const PAGE_SIZE: i32 = 500;

/// Every active connector in one scope, as work the sweep can run.
///
/// The previous snapshot is supplied by the caller rather than read here, because where a
/// snapshot lives is the applier's business and this module does not write.
///
/// # Errors
///
/// [`StoreError`] if the connectors cannot be read.
pub async fn scheduled_for_scope(
    store: &Store,
    scope: Scope,
    limit: i64,
    previous: &(dyn Fn(&LdapConnector) -> BTreeSet<String> + Sync),
) -> Result<Vec<Scheduled>, StoreError> {
    let connectors = store
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(limit)
        .await?;
    Ok(connectors
        .into_iter()
        .map(|connector| Scheduled {
            id: connector.id.to_string(),
            previous: previous(&connector),
            inputs: inputs_for(&connector),
        })
        .collect())
}

/// What one connector row says to read.
///
/// `group_roots` is empty when the connector names no group base, which the sync reads as "every
/// person under the user base is in scope". A group base of `""` would otherwise become a root
/// DN nothing resolves, and an unresolvable root now aborts the walk.
///
/// Migration 0213 is what makes this branch reachable DELIBERATELY. 0212 demanded
/// `group_base_dn <> ''`, which a single space satisfies -- so the arm was reachable, but only by
/// a row whose operator meant the opposite of what the schema recorded, and who was then forced
/// to supply a group filter nothing reads. 0213 keys both checks on `btrim`, so a users-only
/// connector is storable and one value means one thing on both sides.
#[must_use]
pub fn inputs_for(connector: &LdapConnector) -> SyncInputs {
    let group_roots = if connector.group_base_dn.trim().is_empty() {
        Vec::new()
    } else {
        vec![connector.group_base_dn.clone()]
    };
    SyncInputs {
        user_base_dn: connector.user_base_dn.clone(),
        user_filter: connector.user_filter.clone(),
        group_roots,
        // The column is a bounded i32 (0..=64 by CHECK), so this cannot wrap; a negative value
        // could only come from a schema nobody wrote, and 0 is the safe reading of it.
        max_group_depth: u32::try_from(connector.max_group_depth).unwrap_or(0),
        attribute_mapping: connector.attribute_mapping.clone(),
    }
}

/// The URL a connector's host, port and TLS mode describe.
#[must_use]
pub fn url_for(connector: &LdapConnector) -> String {
    let scheme = match connector.tls_mode {
        LdapTlsMode::Ldaps => "ldaps",
        // StartTLS and plaintext both begin on the plain scheme; the client refuses a mismatch.
        LdapTlsMode::StartTls | LdapTlsMode::Plaintext => "ldap",
    };
    format!("{scheme}://{}:{}", connector.host, connector.port)
}

/// The transport mode a connector's column means to the client.
#[must_use]
pub fn tls_mode_for(connector: &LdapConnector) -> TlsMode {
    match connector.tls_mode {
        LdapTlsMode::Ldaps => TlsMode::Ldaps,
        LdapTlsMode::StartTls => TlsMode::StartTls,
        LdapTlsMode::Plaintext => TlsMode::Plaintext,
    }
}

/// Opens a real connection per connector, resolving its bind secret.
pub struct StoreSourceFactory<'a> {
    /// The control-plane store the connectors and secrets live in.
    pub store: &'a Store,
    /// The scope every read is bound to.
    pub scope: Scope,
    /// The key the environment's secrets are sealed under.
    pub master: &'a MasterKey,
    /// The connectors this factory can open, by id.
    ///
    /// Carried rather than re-read per open: the sweep already holds the rows, and re-reading
    /// would let a connector change between being scheduled and being opened.
    pub connectors: Vec<LdapConnector>,
}

/// Why one connector could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// The sweep named a connector this factory does not hold.
    Unknown(String),
    /// The bind secret named by the row could not be read.
    Secret(StoreError),
    /// The secret is not UTF-8, so it is not a bind password.
    SecretNotText,
    /// Connecting or binding failed.
    Connect(crate::ldap_client::DirectoryError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "no connector {id} in this sweep"),
            Self::Secret(e) => write!(f, "the bind secret could not be read: {e}"),
            Self::SecretNotText => write!(f, "the bind secret is not text"),
            Self::Connect(e) => write!(f, "{e}"),
        }
    }
}

impl SourceFactory for StoreSourceFactory<'_> {
    type Source = Directory;
    type Error = OpenError;

    async fn open(&self, scheduled: &Scheduled) -> Result<Directory, OpenError> {
        let connector = self
            .connectors
            .iter()
            .find(|c| c.id.to_string() == scheduled.id)
            .ok_or_else(|| OpenError::Unknown(scheduled.id.clone()))?;

        // THE ONE PRIVILEGED STEP. The row holds a NAME; the password is opened here and lives
        // only as long as the connect.
        let sealed = self
            .store
            .scoped(self.scope)
            .environment_secrets()
            .open_value(self.master, &connector.bind_secret_name)
            .await
            .map_err(OpenError::Secret)?;
        let password = String::from_utf8(sealed).map_err(|_| OpenError::SecretNotText)?;

        Directory::connect(&DirectoryConfig {
            url: url_for(connector),
            tls_mode: tls_mode_for(connector),
            bind_dn: connector.bind_dn.clone(),
            bind_password: password,
            page_size: PAGE_SIZE,
            connect_timeout: CONNECT_TIMEOUT,
        })
        .await
        .map_err(OpenError::Connect)
    }
}

/// Run one sweep over every active connector in a scope.
///
/// Writes nothing: the report is plans and failures, and applying them is a separate decision.
///
/// # Errors
///
/// [`StoreError`] if the connector rows cannot be read. A connector that cannot be OPENED is not
/// an error here -- it is an `Unreachable` entry in the report, which is the whole point of the
/// isolation.
pub async fn sweep_scope(
    store: &Store,
    scope: Scope,
    master: &MasterKey,
    limit: i64,
    previous: &(dyn Fn(&LdapConnector) -> BTreeSet<String> + Sync),
) -> Result<ScopeSweep, StoreError> {
    let connectors = store
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(limit)
        .await?;
    let scheduled: Vec<Scheduled> = connectors
        .iter()
        .map(|connector| Scheduled {
            id: connector.id.to_string(),
            previous: previous(connector),
            inputs: inputs_for(connector),
        })
        .collect();
    let terms: BTreeMap<String, ApplyTerms> = connectors
        .iter()
        .map(|connector| (connector.id.to_string(), terms_for(connector)))
        .collect();
    let factory = StoreSourceFactory {
        store,
        scope,
        master,
        connectors,
    };
    let report = crate::ldap_schedule::sweep(&factory, &scheduled, PER_CONNECTOR_DEADLINE).await;
    Ok(ScopeSweep { report, terms })
}

/// A sweep, plus what the applier needs about each connector that produced a plan.
///
/// The two travel together because the connector rows are read ONCE, in the sweep. Reading them a
/// second time in the applier would be two reads of a table an operator can edit between them,
/// and the pass would apply one connector's plan under another connector's policy.
#[derive(Debug)]
pub struct ScopeSweep {
    /// One entry per scheduled connector.
    pub report: SweepReport,
    /// Keyed by connector id, exactly as [`SweepReport::runs`] is.
    pub terms: BTreeMap<String, ApplyTerms>,
}

/// What applying a connector's plan needs, beyond the plan.
#[derive(Debug, Clone, Copy)]
pub struct ApplyTerms {
    /// Deactivate (the default) or delete, per the connector row.
    pub policy: LdapAbsencePolicy,
    /// Who the audit log names for the writes.
    pub actor: ActorRef,
}

/// The apply terms of one connector row.
///
/// THE ACTOR IS SEEDED FROM THE CONNECTOR ID, not generated. Every write this connector ever makes
/// then carries one service actor, so the audit log answers "what has this directory done to my
/// users" with a single filter. A freshly generated id per pass would scatter one connector's
/// history across as many actors as it has run passes.
#[must_use]
pub fn terms_for(connector: &LdapConnector) -> ApplyTerms {
    ApplyTerms {
        policy: connector.absence_policy,
        actor: ActorRef::service(ServiceId::from_seed_bytes(connector.id.unique_bytes())),
    }
}

/// The clock is read through `Env` like every other timed thing here.
#[must_use]
pub fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}

/// What one pass over every scope observed.
#[derive(Debug, Default, Clone)]
pub struct PassReport {
    /// Scopes read.
    pub scopes: usize,
    /// Connectors that produced a plan.
    pub planned: usize,
    /// Connectors that could not be opened or whose pass failed.
    pub failed: usize,
    /// Plans whose departures are refused, so no applier may act on them.
    pub refusing_departures: usize,
    /// Principals identified only by their DN, across every plan.
    pub rename_fragile: usize,
    /// What was written, summed over every connector in the pass.
    pub applied: ExecuteReport,
}

/// Apply every plan a scope sweep produced.
///
/// Separate from [`run_pass`] because this half needs no directory: a caller can hand it a sweep
/// it built, which is the only way the applied-versus-planned properties are testable without a
/// live LDAP server.
///
/// A connector whose plan carries no terms is SKIPPED rather than defaulted. The only way that
/// happens is a report and a term map that disagree, and guessing a policy -- particularly the
/// irreversible one -- from a disagreement is not a guess worth making.
pub async fn apply_sweep(
    store: &Store,
    scope: Scope,
    env: &Env,
    sweep: &ScopeSweep,
) -> ExecuteReport {
    let mut total = ExecuteReport::default();
    for (id, outcome) in &sweep.report.runs {
        let Outcome::Planned(plan) = outcome else {
            continue;
        };
        let Some(terms) = sweep.terms.get(id) else {
            tracing::error!(
                connector = %id,
                "ldap sync produced a plan for a connector whose policy it does not have; nothing \
                 applied for it"
            );
            continue;
        };
        let changes = ChangeSet::from_plan(plan, terms.policy);
        if let Some(refusal) = &changes.withheld {
            tracing::warn!(
                connector = %id,
                reason = %refusal,
                "ldap sync withheld every removal for this connector"
            );
        }
        let report = execute(store, scope, env, terms.actor, &changes).await;
        for (principal, error) in &report.failures {
            tracing::warn!(
                connector = %id,
                principal = %principal,
                %error,
                "ldap sync could not apply one change; the rest of the connector continued"
            );
        }
        total.absorb(report);
    }
    total
}

/// Run one sweep across every scope the source enumerates, and apply what it plans.
///
/// # The previous snapshot is empty, so no departure is ever computed
///
/// Every connector is swept against an empty previous set, which makes every principal an arrival
/// and leaves the departure set empty. A pass therefore PROVISIONS and never removes. That is a
/// deliberate intermediate state, not an oversight: absence detection needs a snapshot of what the
/// last pass saw, that snapshot is a stored artifact this pass does not yet own, and inferring one
/// from the accounts that happen to carry an external id would deactivate every SCIM-provisioned
/// user the moment an LDAP connector is added. Stated here rather than implied, because
/// "0 removals" from this pass means "not asked", not "nobody left".
///
/// # Errors
///
/// [`StoreError`] if a scope cannot be enumerated or its connectors cannot be read. A connector
/// that cannot be OPENED is not an error here: it is a failure recorded against that connector,
/// which is the entire point of the isolation.
pub async fn run_pass(
    store: &Store,
    scopes: &dyn ScopeSource,
    env: &Env,
    master: &MasterKey,
    batch: i64,
) -> Result<PassReport, StoreError> {
    let mut report = PassReport::default();
    for scope in scopes.scopes().await? {
        report.scopes += 1;
        let sweep = sweep_scope(store, scope, master, batch, &|_| BTreeSet::new()).await?;
        fold_scope(store, scope, env, &sweep, &mut report).await;
    }
    Ok(report)
}

/// Everything a pass does with ONE scope's sweep: count it, warn about it, and apply it.
///
/// SEPARATE FROM [`run_pass`] because the pass's remaining three lines need a directory to reach,
/// and this does not. Before the split, deleting the apply call from the pass left every test in
/// the repository green -- the pass's whole reason for existing was observable only by a live
/// directory test that CI does not run.
pub async fn fold_scope(
    store: &Store,
    scope: Scope,
    env: &Env,
    sweep: &ScopeSweep,
    report: &mut PassReport,
) {
    for (id, outcome) in &sweep.report.runs {
        match outcome {
            Outcome::Planned(plan) => {
                report.planned += 1;
                report.rename_fragile += plan.rename_fragile;
                if plan.departures.is_err() {
                    report.refusing_departures += 1;
                    tracing::warn!(
                        connector = %id,
                        truncated_at = ?plan.groups_truncated_at,
                        "ldap sync read a directory it could not see all of; no departure \
                         may be concluded from this pass"
                    );
                }
            }
            other => {
                report.failed += 1;
                tracing::warn!(
                    connector = %id,
                    reason = %other.failure().unwrap_or(std::borrow::Cow::Borrowed("unknown")),
                    "ldap connector did not produce a plan"
                );
            }
        }
    }
    report
        .applied
        .absorb(apply_sweep(store, scope, env, sweep).await);
}
