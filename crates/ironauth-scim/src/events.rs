// SPDX-License-Identifier: MIT OR Apache-2.0

//! The events a SCIM write announces (issue #136).
//!
//! # Why a provisioning write announces anything at all
//!
//! Criterion 3 asks that deprovisioning reach "downstream apps ... even if they hold no live
//! session". The cascade a termination already runs is entirely INTERNAL: sessions end,
//! refresh families die, back-channel logout is delivered to relying parties that HAVE a
//! session. An application holding no session for the person learns nothing, and an
//! application that keeps its own copy of the directory (the ordinary case for anything doing
//! entitlement checks offline) keeps serving somebody the identity provider terminated.
//!
//! So the writes here emit onto the same queue every other producer uses. One enqueue reaches
//! both delivery surfaces: `WEBHOOK_EVENT_CONSUMER` rows are what the webhook fan-out explodes
//! into per-endpoint deliveries AND what the ordered event feed pages over, so a consumer that
//! cannot take a push replays exactly the same events by cursor.
//!
//! # Two grains, and both are emitted
//!
//! A SCIM deprovisioning is two facts, and which one a receiver needs depends on what it
//! keeps:
//!
//!   * the ORGANIZATION grain (`user.deprovisioned`, `user.deactivated`): this directory no
//!     longer holds this person. Always true of a SCIM termination.
//!   * the ACCOUNT grain (`user.state_changed`): the person can no longer sign in anywhere in
//!     this environment. True only when no OTHER organization still holds them active.
//!
//! Emitting only the account grain would say nothing at all about a person who belongs to two
//! organizations and was terminated by one, which is the case this distinction exists for.
//! Emitting only the organization grain would leave a consumer unable to tell a directory
//! removal from an account that stopped authenticating. They are separate types on separate
//! writes, each transactional with the write it announces.
//!
//! # The idempotency key is the event id
//!
//! `DomainEvent::id` becomes `outbox_messages.idempotency_key`, which becomes the `webhook-id`
//! header of every delivery and the `id` on the envelope a feed reader sees. A receiver that
//! is delivered the same event twice (the queue is at-least-once by design) sees one id twice
//! and drops the second.
//!
//! It is minted fresh per WRITE rather than derived from the subject, and that is deliberate
//! rather than convenient: the enqueue raises a unique violation on a repeated key, inside the
//! caller's transaction, so a derived key would make the SECOND deprovisioning of a person
//! fail the whole request permanently. A client re-sending a `DELETE` after a network timeout
//! would be answered `500` forever.

use ironauth_store::{OwnedDomainEvent, Scope};

use crate::server::ScimState;
use crate::users::epoch_micros;

/// The type a `DELETE` announces: the person is out of this organization's directory.
pub(crate) const USER_DEPROVISIONED: &str = "user.deprovisioned";

/// The type `active: false` announces: the person stays in the directory and cannot use it.
pub(crate) const USER_DEACTIVATED: &str = "user.deactivated";

/// The account-grain type, shared with the management API: the account's own lifecycle state
/// moved. Emitted by the reconciliation, and only when the state actually changed.
pub(crate) const USER_STATE_CHANGED: &str = "user.state_changed";

/// Build an organization-grain provisioning event, or `None` if the catalog does not register
/// `event_type`.
///
/// `None` rather than a panic because that is what the catalog's builder returns and what the
/// callers already have to handle: an unregistered type is refused at the fan-out anyway, and
/// the producer failing to build one means the write it would have ridden never happens.
pub(crate) fn membership_event(
    state: &ScimState,
    scope: Scope,
    event_type: &str,
    user: &str,
    organization: &str,
) -> Option<OwnedDomainEvent> {
    envelope_for(
        state,
        scope,
        event_type,
        user,
        &serde_json::json!({
            "user_id": user,
            "organization_id": organization,
        }),
    )
}

/// Build the account-grain `user.state_changed` event.
///
/// `hard_kill` is on the payload because it changes what the transition DID: it decides
/// whether the person's OFFLINE refresh families died with their sessions, and a receiver
/// cannot work that out afterwards.
pub(crate) fn state_changed_event(
    state: &ScimState,
    scope: Scope,
    user: &str,
    to: &str,
    hard_kill: bool,
) -> Option<OwnedDomainEvent> {
    envelope_for(
        state,
        scope,
        USER_STATE_CHANGED,
        user,
        &serde_json::json!({
            "user_id": user,
            "state": to,
            "hard_kill": hard_kill,
        }),
    )
}

/// Mint an id and wrap `payload` in the catalog's envelope.
///
/// The SUBJECT is the user in every case, including the organization-grain events. The subject
/// is what orders one entity's events against each other, and the entity these are about is
/// the person: a deactivate and the account transition it caused must not be exploded out of
/// order, and keying the first on the organization would put them in different ordering groups
/// where nothing holds them in sequence.
fn envelope_for(
    state: &ScimState,
    scope: Scope,
    event_type: &str,
    subject: &str,
    payload: &serde_json::Value,
) -> Option<OwnedDomainEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        epoch_micros(state) / 1000,
        payload,
    )?;
    Some(OwnedDomainEvent {
        id,
        subject: subject.to_string(),
        envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::{USER_DEACTIVATED, USER_DEPROVISIONED, USER_STATE_CHANGED};

    /// Every type this crate emits is in the catalog.
    ///
    /// This is what keeps the `else` arms at the three producers unreachable. `envelope`
    /// returns `None` for an unregistered type, and the producers answer that with a 500
    /// rather than an eventless write, so a typo in a constant here would turn every SCIM
    /// deprovisioning into a server error. A misspelling is not a hypothetical: the constants
    /// are strings, the registry is a separate array of strings, and nothing else compares
    /// them.
    ///
    /// It also fails the other way, which is the direction that matters more: a type REMOVED
    /// from the registry (or renamed there) breaks here rather than at the first live
    /// termination.
    #[test]
    fn every_type_this_crate_emits_is_registered() {
        for wire in [USER_DEPROVISIONED, USER_DEACTIVATED, USER_STATE_CHANGED] {
            assert!(
                ironauth_store::event_catalog::registered(wire).is_some(),
                "{wire} is emitted by this crate and is not in the event catalog"
            );
        }
    }
}
