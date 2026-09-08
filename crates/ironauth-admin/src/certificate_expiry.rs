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
/// # Errors
///
/// [`StoreError`] if reading the due set fails, or if recording a notice fails for any reason
/// other than the two races above. A pass stops at the first such failure and reports it: the
/// pairs it has already recorded stay recorded, and the next pass picks up the rest, because
/// every pair is decided independently by its own row.
pub async fn run_once(
    store: &Store,
    env: &Env,
    scope: Scope,
    leads_secs: &[i64],
    limit: i64,
) -> Result<SweepReport, StoreError> {
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Encryption)?
            .as_micros(),
    )
    .map_err(|_| StoreError::Encryption)?;

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
            // The type is registered, so this is unreachable; a build that removed it would fail
            // the catalog gate long before here.
            return Err(StoreError::Encryption);
        };

        let certificate =
            ironauth_store::SamlCertificateId::parse_in_scope(&item.certificate_id, &scope)
                .map_err(|_| StoreError::NotFound)?;

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
            Err(error) => return Err(error),
        }
    }
    Ok(report)
}
