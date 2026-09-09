// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running every active connector, one pass each (issue #142).
//!
//! # One connector's bad day is its own
//!
//! A tenant may have several directories configured, and they fail independently: a bind password
//! rotated on one, a firewall change in front of another, a third perfectly healthy. The sweep
//! therefore runs each to completion and collects outcomes rather than returning on the first
//! error, and [`SweepReport`] carries one entry per connector INCLUDING the ones that failed.
//!
//! That last part is the property worth stating, because the tempting shape is a `Vec<SyncPlan>`
//! of whatever worked. A failed connector missing from the report is indistinguishable from a
//! connector with nothing to do -- and the thing on the other end of this is deprovisioning, so
//! "nothing to do" and "could not look" must never render the same.
//!
//! # It still does not apply anything
//!
//! Like [`crate::ldap_sync::plan`], this writes nothing. It produces one plan per healthy
//! connector, each carrying its own [`crate::ldap_diff::DepartureRefusal`] where the read was
//! short. A sweep being "successful" says nothing about whether any individual plan may be acted
//! on.

use crate::ldap_groups::GroupSource;
use crate::ldap_sync::{EntrySource, SyncError, SyncInputs, plan};
use ironauth_env::Env;
use std::collections::{BTreeMap, BTreeSet};

/// One connector the sweep should run.
pub struct Scheduled {
    /// How the connector is named in the report and in logs.
    pub id: String,
    /// What to read.
    pub inputs: SyncInputs,
    /// The stable ids the previous run recorded.
    pub previous: BTreeSet<String>,
}

/// Where a sweep gets a live source for one connector.
///
/// A trait rather than a closure so the failure to OPEN a connector -- a refused bind, a
/// certificate that will not validate -- is part of the same isolation story as a failure while
/// reading. Both land in the report against the connector that caused them.
pub trait SourceFactory {
    /// The source this factory produces.
    type Source: EntrySource + GroupSource + Sync;
    /// Why opening one might fail.
    type Error: std::fmt::Display;

    /// Open a connection for one connector.
    ///
    /// # Errors
    ///
    /// Whatever connecting and binding fails with.
    fn open(
        &self,
        scheduled: &Scheduled,
    ) -> impl std::future::Future<Output = Result<Self::Source, Self::Error>> + Send;
}

/// What one connector's pass produced.
#[derive(Debug)]
pub enum Outcome {
    /// The connector took longer than the sweep's per-connector deadline.
    ///
    /// ITS OWN VARIANT because it is the failure that would otherwise not be one. `ldap3`'s
    /// connection timeout bounds the TCP connect and nothing after it: a directory that accepts
    /// the socket and never answers the bind leaves `open` pending for ever -- measured still
    /// pending at 8s under a 1s connection timeout. Without a deadline here, one such directory
    /// stops every connector behind it, which is exactly the isolation this module exists for.
    TimedOut {
        /// How long it was given.
        after: std::time::Duration,
    },
    /// The pass ran and produced a plan. The plan may still refuse its own departures.
    Planned(Box<crate::ldap_sync::SyncPlan>),
    /// The connector could not be opened.
    ///
    /// Distinct from [`Self::Failed`] because it is the diagnosis an operator acts on first: a
    /// bind that will not open is a credential or a network fact, not a directory-shape fact.
    Unreachable(String),
    /// The pass ran and could not finish.
    Failed(String),
}

impl Outcome {
    /// Whether this connector produced a plan at all.
    #[must_use]
    pub fn is_planned(&self) -> bool {
        matches!(self, Self::Planned(_))
    }

    /// The operator-facing reason, when there is one.
    #[must_use]
    pub fn failure(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::Planned(_) => None,
            Self::Unreachable(why) | Self::Failed(why) => Some(std::borrow::Cow::Borrowed(why)),
            Self::TimedOut { after } => Some(std::borrow::Cow::Owned(format!(
                "gave up after {}s",
                after.as_secs()
            ))),
        }
    }
}

/// Every connector's outcome, in the order they were scheduled.
#[derive(Debug)]
pub struct SweepReport {
    /// One entry per SCHEDULED connector. Never shorter than the input.
    pub runs: Vec<(String, Outcome)>,
    /// When each connector's attempt began and how long it took, keyed as [`Self::runs`] is.
    ///
    /// MEASURED HERE because this is the only place that knows: the deadline wraps open and read
    /// together, so the elapsed time of that future IS the connector's sync duration. A caller
    /// timing the whole scope could only divide, and a caller timing nothing at all would have to
    /// invent the number -- which is what the health row carried before this existed.
    pub timings: BTreeMap<String, RunTiming>,
}

/// When one connector's attempt began, and how long it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunTiming {
    /// Microseconds since the Unix epoch, read just before the attempt started.
    pub started_at_unix_micros: i64,
    /// Wall-clock milliseconds the attempt took, deadline included.
    pub duration_ms: i64,
}

impl SweepReport {
    /// The connectors that could not produce a plan, with their reasons.
    #[must_use]
    pub fn failures(&self) -> Vec<(&str, std::borrow::Cow<'_, str>)> {
        self.runs
            .iter()
            .filter_map(|(id, outcome)| outcome.failure().map(|why| (id.as_str(), why)))
            .collect()
    }

    /// Whether every scheduled connector produced a plan.
    ///
    /// FALSE does not mean the sweep should be retried wholesale: the connectors that succeeded
    /// have usable plans, which is the point of running them independently.
    #[must_use]
    pub fn every_connector_planned(&self) -> bool {
        self.runs.iter().all(|(_, outcome)| outcome.is_planned())
    }
}

/// Run one pass for each scheduled connector.
///
/// Never returns early. A connector that cannot be opened, or whose pass fails, is recorded and
/// the sweep continues.
pub async fn sweep<F>(
    factory: &F,
    scheduled: &[Scheduled],
    per_connector: std::time::Duration,
    env: &Env,
) -> SweepReport
where
    F: SourceFactory + Sync,
    SyncError: From<<F::Source as EntrySource>::Error> + From<<F::Source as GroupSource>::Error>,
{
    let mut runs = Vec::with_capacity(scheduled.len());
    let mut timings = BTreeMap::new();
    for connector in scheduled {
        let started_at_unix_micros = now_micros(env);
        let began = env.clock().monotonic();
        // THE DEADLINE COVERS OPEN AND READ TOGETHER, because either can hang. `ldap3`'s
        // connection timeout bounds the TCP connect only -- a directory that accepts the socket
        // and never answers the bind leaves `open` pending indefinitely -- and a search that
        // stalls mid-page has no bound at all. Without this the isolation is a fiction: one
        // unresponsive directory stops every connector scheduled behind it.
        let attempt = tokio::time::timeout(per_connector, async {
            match factory.open(connector).await {
                Err(why) => Outcome::Unreachable(why.to_string()),
                Ok(source) => match plan(&source, &connector.inputs, &connector.previous).await {
                    Ok(p) => Outcome::Planned(Box::new(p)),
                    Err(why) => Outcome::Failed(why.to_string()),
                },
            }
        })
        .await;
        // THE MONOTONIC CLOCK FOR THE DURATION, the wall clock for the instant, both through
        // `Env` like every other time read here. A duration measured from two wall-clock samples
        // goes backwards across an NTP step, and a negative duration is refused by the health
        // column.
        timings.insert(
            connector.id.clone(),
            RunTiming {
                started_at_unix_micros,
                duration_ms: i64::try_from(
                    env.clock()
                        .monotonic()
                        .saturating_duration_since(began)
                        .as_millis(),
                )
                .unwrap_or(i64::MAX),
            },
        );
        runs.push((
            connector.id.clone(),
            attempt.unwrap_or(Outcome::TimedOut {
                after: per_connector,
            }),
        ));
    }
    SweepReport { runs, timings }
}

/// The wall clock, read through `Env` like every other timed thing here.
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
