// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of the certificate expiry sweep (issue #141).
//!
//! # What this does and what it deliberately does not
//!
//! #141's first criterion has two halves: a certificate entering its expiry window "triggers
//! notifications to the org's IT contacts at each configured lead time" AND "fires the renewal
//! webhook". This is the second half, end to end: every (certificate, lead) pair that has crossed
//! its threshold and not been announced gets a `saml_certificate.expiry_announced` event carrying the
//! organization whose contacts it concerns, recorded in the same transaction so the announcement
//! and the record are one fact.
//!
//! The first half -- composing and sending mail to those contacts -- goes through the messaging
//! subsystem with its own send hygiene, and is not here. Saying so matters: a reader looking for
//! "does a customer actually get told" must not find this and conclude yes.
//!
//! # Why a pass rather than a schedule
//!
//! What triggers a pass is left to the caller, and that is the open question rather than an
//! oversight. `offboarding_worker` records the tradeoff this codebase has already reasoned
//! through: a periodic sweep queries every scope on a timer for ever and has no actor to
//! attribute anything to, while a delayed message exists only when there is something to do. A
//! certificate's expiry is knowable the moment it is pinned, so the scheduled-wake-up shape fits
//! -- and the configured lead set can change after pinning, which is exactly why the DECISION of
//! what is owed lives in `due()` against current configuration rather than in the wake-up.
//!
//! Making the pass a function the caller drives keeps both options open and makes this testable
//! without inventing a scheduler.

use ironauth_env::Env;
use ironauth_store::outbox::ScopeSource;
use ironauth_store::{DomainEvent, Scope, Store, StoreError};

/// Why a pass could not finish.
///
/// # Why not `StoreError`
///
/// Three of these have nothing to do with the store, and the nearest variants misdescribe them:
/// `Encryption` renders as "envelope decryption failed" and `Database` as a persistence failure,
/// so borrowing either would put a wrong sentence in front of whoever is paged. An earlier
/// version used `Encryption` for all three, which a review caught.
#[derive(Debug)]
pub enum SweepError {
    /// The store could not be read or written.
    Store(StoreError),
    /// The clock is before the Unix epoch, or the microsecond count will not fit an `i64`.
    ///
    /// NOT THE CALLER'S PROBLEM AND NOT RECOVERABLE BY RETRY, which is why it is its own arm
    /// rather than folded into `Store`: a pass that keeps failing on this needs the clock looked
    /// at, and a message about persistence would send somebody to the wrong place.
    Clock,
    /// The registry would not build an envelope for a type it is supposed to carry.
    ///
    /// Unreachable in a build whose catalog still holds `saml_certificate.expiry_announced`. It is NOT
    /// caught by the catalog gate first, as an earlier comment claimed: that gate is a freshness
    /// check over the generated docs and notices the REGISTRY changing, not this call site.
    Envelope,
    /// A certificate id in a row of this scope did not parse as one.
    ///
    /// Distinct from a vanished work item: the row exists and its id is unusable, which is a
    /// fault rather than a race, so it is raised rather than counted.
    UnreadableId,
}

impl core::fmt::Display for SweepError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => {
                write!(f, "the expiry ledger could not be read or written: {error}")
            }
            Self::Clock => f.write_str("the clock is before the Unix epoch or out of range"),
            Self::Envelope => f.write_str("the event registry would not build an expiry notice"),
            Self::UnreadableId => f.write_str("a stored certificate id did not parse"),
        }
    }
}

impl std::error::Error for SweepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for SweepError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Pairs announced and recorded.
    pub announced: usize,
    /// Pairs another pass had already taken between this one reading and writing.
    ///
    /// NOT AN ERROR, AND COUNTED SEPARATELY SO IT IS NOT READ AS ONE. Two sweeps racing over one
    /// certificate is the ordinary case for a job an operator can run twice; the ledger's primary
    /// key means exactly one of them announces and the other learns it here.
    pub already_taken: usize,
    /// Pairs whose certificate was unpinned between this pass reading and writing.
    ///
    /// ALSO NOT AN ERROR. An expiry warning is precisely what prompts an operator to replace a
    /// certificate, so losing the race to the renewal it asked for is a success of the feature.
    pub vanished: usize,
}

/// Run one pass for one scope.
///
/// # The store must be the CONTROL-plane one
///
/// 0208 grants the alert ledger to `ironauth_control` alone -- SELECT and INSERT both -- so a
/// pass handed the data-plane store fails on its first READ, before it has anything to record.
/// An earlier version said "on its first insert", which is wrong about where it breaks and would
/// send somebody looking at the write path. The type cannot express the requirement, because
/// both planes are a `Store`, so it is said here.
///
/// # Errors
///
/// [`SweepError::Store`] if reading the due set or recording a notice fails.
///
/// [`SweepError::Clock`] if the clock is before the Unix epoch or its microsecond count will not
/// fit an `i64`; [`SweepError::Envelope`] if the registry will not build a notice for a type it
/// carries; [`SweepError::UnreadableId`] if a certificate id in a row of this scope will not
/// parse as one. All three reported `StoreError::Encryption` until a review pointed out that it
/// renders as "envelope decryption failed", which none of them is.
///
/// NOT a `Conflict` or a `NotFound`: both are races rather than faults, and both are COUNTED in
/// the report rather than returned. See [`SweepReport`].
///
/// A pass stops at the first genuine failure. The pairs it has already recorded stay recorded
/// and the next pass picks up the rest, because every pair is decided independently by its own
/// row.
pub async fn run_once(
    store: &Store,
    env: &Env,
    scope: Scope,
    leads_secs: &[i64],
    limit: i64,
) -> Result<SweepReport, SweepError> {
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SweepError::Clock)?
            .as_micros(),
    )
    .map_err(|_| SweepError::Clock)?;

    let alerts = store.scoped(scope).saml_certificate_alerts();
    let due = alerts.due(now, leads_secs, limit).await?;

    let mut report = SweepReport::default();
    for item in due {
        let event_id = format!("evt_{}_{}", item.certificate_id, item.lead_secs);
        let Some(envelope) = ironauth_store::event_catalog::envelope(
            &event_id,
            "saml_certificate.expiry_announced",
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            now / 1000,
            &serde_json::json!({
                "saml_certificate_id": item.certificate_id,
                "saml_connection_id": item.connection_id,
                "organization_id": item.organization_id,
                "lead_secs": item.lead_secs,
                "not_after_unix_ms": item.not_after_unix_micros / 1000,
            }),
        ) else {
            // Unreachable in a build whose catalog still carries the type. NOT "the gate would
            // catch it first": `event-catalog.sh` is a freshness check over the generated docs,
            // so it notices the REGISTRY changing rather than this call site failing. If the two
            // ever disagree it is a server fault, which is what it now reports.
            return Err(SweepError::Envelope);
        };

        // THE ID CAME OUT OF `due()`, which read it from a row in THIS scope, so a parse failure
        // means the column holds something the type cannot represent -- a server fault rather
        // than "no such certificate", and propagated rather than counted as a vanished work
        // item, which would hide it.
        let certificate =
            ironauth_store::SamlCertificateId::parse_in_scope(&item.certificate_id, &scope)
                .map_err(|_| SweepError::UnreadableId)?;

        match alerts
            .record_sent(
                env,
                &certificate,
                item.lead_secs,
                now,
                Some(&DomainEvent {
                    id: &event_id,
                    subject: &item.certificate_id,
                    envelope: &envelope,
                }),
            )
            .await
        {
            Ok(()) => report.announced += 1,
            // BOTH RACES ARE COUNTED, NOT PROPAGATED. See `SweepReport`: neither is a fault, and
            // treating either as one would make an ordinary concurrent pass look like an outage.
            Err(StoreError::Conflict) => report.already_taken += 1,
            Err(StoreError::NotFound) => report.vanished += 1,
            Err(error) => return Err(SweepError::Store(error)),
        }
    }
    Ok(report)
}

/// The lead set a configured list of DAYS becomes, in seconds.
///
/// # Why this is a function and not an inline `map`
///
/// Three of the four things it does are corrections a `map` would not make, and each one is a
/// configuration a deployment can actually write.
///
/// A ZERO LEAD IS DROPPED, because it can never match. The due query selects
/// `not_after > now AND not_after <= now + lead`, which for a lead of zero is unsatisfiable: a
/// zero threshold warns nobody at any time. It reads like "warn me at expiry" and is not, so
/// keeping it would leave an operator with a configured warning that silently never fires.
///
/// AN EARLIER VERSION OF THIS PARAGRAPH gave a different reason -- that a zero reaches
/// `envelope()`, fails its `minimum: 1` schema and turns every pass into a server fault. That
/// failure cannot occur, because the row never comes back from `due()` to be announced. The
/// behaviour was right and the justification was invented; it had been copied into five
/// artifacts before a review checked it.
///
/// DUPLICATES COLLAPSE, and here the ordering step is what makes that work: `Vec::dedup` removes
/// only ADJACENT equal elements, so `[7, 30, 7]` collapses only after sorting. `due()` also
/// unnests DISTINCT, so a duplicate reaching it is harmless -- which makes this a tidiness of
/// the returned vector rather than a correctness fix, and it is worth saying so rather than
/// claiming a bug it prevents.
///
/// THE ORDER IS DESCENDING -- longest lead first, so the THIRTY-day threshold heads the list.
/// An earlier version of this sentence called that "the earliest warning first", which is
/// backwards: the thirty-day threshold is the earliest warning in TIME and the last of the three
/// a certificate crosses. Nothing downstream depends on either reading, because `due()` orders
/// its own rows `BY c.not_after, c.id, l.lead_secs` and announces the SHORTEST crossed lead
/// first regardless of how this vector is arranged. What the order actually decides is the shape
/// of the startup log line and of this function's return value.
#[must_use]
pub fn leads_from_days(days: &[u32]) -> Vec<i64> {
    const SECS_PER_DAY: i64 = 24 * 60 * 60;

    let mut leads: Vec<i64> = days
        .iter()
        .filter(|day| **day > 0)
        .map(|day| i64::from(*day) * SECS_PER_DAY)
        .collect();
    leads.sort_unstable_by(|left, right| right.cmp(left));
    leads.dedup();
    leads
}

/// What one pass over every scope did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Scopes whose pass completed, whether or not it announced anything.
    pub swept: usize,
    /// Scopes whose pass returned an error.
    ///
    /// COUNTED RATHER THAN RETURNED. One scope's failure must not end the pass: a single tenant
    /// with a corrupt certificate id would otherwise stop every other tenant being warned, and
    /// the tenants that lose their warning are the ones that did nothing wrong.
    pub failed: usize,
    /// Notices announced across every scope.
    pub announced: usize,
}

/// Run one pass over every scope the source reports.
///
/// `limit` bounds ONE SCOPE's pass, not the whole sweep: it is handed to each `run_once` in
/// turn, so a sweep over N scopes may announce up to N times it. That is the useful bound --
/// it caps the size of any single transaction -- but it is not a cap on the pass, and both
/// generated config artifacts said "one pass" until a review read them.
///
/// # Errors
///
/// Only if the scope source itself cannot be read; a scope that fails is counted in the report.
/// A pass that can enumerate nothing is different in kind from one whose tenants failed: there
/// is no work list at all, and reporting "0 swept, 0 failed" would look identical to a healthy
/// deployment with no tenants.
pub async fn run_pass(
    store: &Store,
    env: &Env,
    scopes: &dyn ScopeSource,
    leads_secs: &[i64],
    limit: i64,
) -> Result<PassReport, StoreError> {
    let mut report = PassReport::default();
    if leads_secs.is_empty() {
        // Alerting is off, so there is nothing to enumerate scopes FOR. One round trip is saved
        // -- the scope listing itself -- and no more: `due()` returns immediately on an empty
        // lead set without querying, so the per-scope passes would each have cost nothing. An
        // earlier version of this comment claimed a database round trip per scope, which
        // overstates the saving by the whole of it.
        return Ok(report);
    }
    for scope in scopes.scopes().await? {
        match run_once(store, env, scope, leads_secs, limit).await {
            Ok(one) => {
                report.swept += 1;
                report.announced += one.announced;
            }
            Err(error) => {
                report.failed += 1;
                tracing::error!(
                    target: "ironauth.certificate_expiry",
                    tenant = %scope.tenant(),
                    environment = %scope.environment(),
                    %error,
                    "certificate expiry pass failed for this scope; other scopes continue"
                );
            }
        }
    }
    Ok(report)
}

/// What one retirement pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetireReport {
    /// Certificates unpinned.
    pub retired: usize,
    /// Certificates that were gone by the time the pass reached them.
    ///
    /// NOT AN ERROR. An operator unpinning a superseded certificate by hand while a pass is
    /// deciding to do the same thing is the ordinary case, not a rare one: they are both acting
    /// on the same observation.
    pub vanished: usize,
}

/// Retire certificates whose rollover window has closed, for one scope.
///
/// # Why this is a separate pass from the expiry sweep
///
/// They read opposite ends of the same lifecycle -- one warns before an expiry, the other tidies
/// up after a replacement -- and only this one WRITES to the certificate table. Keeping them
/// separate means a deployment that wants warnings without automatic retirement gets it by
/// setting the window to zero, and a fault in one does not stop the other.
///
/// # Errors
///
/// [`SweepError::Store`] if reading the retirable set fails. A single certificate that cannot be
/// unpinned stops the pass, because the same failure will meet the next one and continuing would
/// turn one persistence fault into a log line per certificate.
pub async fn retire_once(
    store: &Store,
    env: &Env,
    scope: Scope,
    window_secs: i64,
    limit: i64,
) -> Result<RetireReport, SweepError> {
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SweepError::Clock)?
            .as_micros(),
    )
    .map_err(|_| SweepError::Clock)?;

    let mut report = RetireReport::default();
    if window_secs <= 0 {
        // RETIREMENT IS OFF, and the guard belongs HERE rather than only at the caller. A window
        // of zero means "keep every pin until somebody removes it"; passed straight through to
        // the query it means "a replacement pinned zero seconds ago is old enough", which
        // retires every superseded certificate at once -- the exact opposite of what the setting
        // says. The boot path also skips the pass, but that is an optimisation, and a guard that
        // lives only in one caller is a guard the next caller does not get.
        return Ok(report);
    }
    let retirable = store
        .scoped(scope)
        .saml_connections()
        .retirable(now, window_secs, limit)
        .await
        .map_err(SweepError::Store)?;
    for certificate in retirable {
        match store
            .scoped(scope)
            .acting(
                ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(env)),
                ironauth_store::CorrelationId::generate(env),
            )
            .saml_connections()
            .unpin_certificate(env, &certificate.id, None)
            .await
        {
            Ok(()) => report.retired += 1,
            // ALREADY GONE. Counted rather than raised, for the reason `SweepReport::vanished`
            // gives: losing a race to the operator doing the same thing by hand is the feature
            // working, not a fault.
            Err(ironauth_store::StoreError::NotFound) => report.vanished += 1,
            Err(error) => return Err(SweepError::Store(error)),
        }
    }
    Ok(report)
}
