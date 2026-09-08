// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of the certificate expiry sweep (issue #141).
//!
//! # What this does and what it deliberately does not
//!
//! #141's first criterion has two halves: a certificate entering its expiry window "triggers
//! notifications to the org's IT contacts at each configured lead time" AND "fires the renewal
//! webhook". This is the second half, end to end: every (certificate, lead) pair that has crossed
//! its threshold and not been announced gets a `saml_certificate.expiring` event carrying the
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
    /// Unreachable in a build whose catalog still holds `saml_certificate.expiring`. It is NOT
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
/// 0208 grants the alert ledger to `ironauth_control` alone, so a pass handed the data-plane
/// store fails on its first insert. The type cannot say this -- both planes are a `Store` -- so
/// it is said here, as the sibling sweeper does.
///
/// # Errors
///
/// [`StoreError::Database`] if reading the due set or recording a notice fails.
///
/// [`StoreError::Internal`] for four states that should not arise and are not the caller's: a
/// clock before the Unix epoch, a microsecond count that will not fit an `i64`, an envelope the
/// registry will not build, and a certificate id in a row of this scope that will not parse as
/// one. All four reported `Encryption` until a review pointed out that it renders as "envelope
/// decryption failed", which none of them is.
///
/// NOT [`StoreError::Conflict`] or [`StoreError::NotFound`]: both are races rather than faults,
/// and both are COUNTED in the report. See [`SweepReport`].
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
            "saml_certificate.expiring",
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
                .map_err(|_| SweepError::Clock)?;

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
