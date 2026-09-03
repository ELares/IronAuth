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
//! So the writes here emit onto the same queue every other producer uses, and ONE ENQUEUE
//! REACHES BOTH DELIVERY SURFACES: the webhook fan-out claims `WEBHOOK_EVENT_CONSUMER` rows and
//! explodes each into one delivery per endpoint, while the ordered feed pages over the same
//! rows, so a consumer that cannot take a push replays exactly the same events by cursor.
//!
//! The feed's read is the WIDER of the two and it is worth being exact about which is which:
//! `OutboxRepo::events_after` filters on scope, sequence and the visibility watermark and names
//! no consumer at all, so it serves every outbox row in the scope rather than only the events.
//! What is true is the direction this relies on: an event enqueued here is on the feed and is
//! delivered. The converse, that everything on the feed is an event, is not, and
//! `repository.rs`'s own note on that query says so.
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
//! rather than convenient: the enqueue raises a unique violation on a repeated key, INSIDE the
//! caller's transaction, so a derived key would make the second deprovisioning of one person
//! fail the whole request permanently. That is not hypothetical -- a person deprovisioned,
//! re-provisioned when they return, and deprovisioned again is an ordinary employment history,
//! and the second `DELETE` would answer `500` for as long as the first event was retained.
//!
//! A retried `DELETE` is NOT that case, and an earlier version of this paragraph offered it as
//! the illustration: the first delete removes the membership, so `addressed_user` answers the
//! retry `404` before anything reaches the enqueue.
//!
//! What a per-write id costs is the converse: two events for one change cannot be collapsed by
//! a receiver deduplicating on the id. That is why the writes here refuse to announce a change
//! they did not make -- the activation upsert's conflict arm makes a repeated `active: false` a
//! no-op, and a `DELETE` after a `DELETE` is a 404.

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

/// A person was bound into an organization group, or unbound from one (issue #136,
/// criterion 4). Shared with the management API, which emits the same pair for an operator's
/// write: a group binding pushed by an identity provider confers exactly what an
/// operator-created one does, so it must announce itself the same way.
pub(crate) const GROUP_MEMBER_ADDED: &str = "org_group.member_added";
/// The removal half of [`GROUP_MEMBER_ADDED`].
pub(crate) const GROUP_MEMBER_REMOVED: &str = "org_group.member_removed";
/// What one group write did to the group's membership SET, as a delta.
pub(crate) const GROUP_MEMBERSHIP_CHANGED: &str = "org_group.membership_changed";

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

/// Build an `org_group.member_added` or `org_group.member_removed` event (issue #136,
/// criterion 4).
///
/// The SUBJECT is the group, matching the management producer of the same types: changes to
/// one group must stay ordered against each other, which is what lets a consumer apply them as
/// a sequence. Keying on the membership instead would put a group's own adds and removes in
/// different ordering groups.
pub(crate) fn group_member_event(
    state: &ScimState,
    scope: Scope,
    event_type: &str,
    group: &str,
    organization: &str,
    membership: &str,
) -> Option<OwnedDomainEvent> {
    envelope_for(
        state,
        scope,
        event_type,
        group,
        &serde_json::json!({
            "org_group_id": group,
            "organization_id": organization,
            "membership_id": membership,
        }),
    )
}

/// Build the `org_group.membership_changed` delta for one group write (issue #136,
/// criterion 4).
///
/// Criterion 4 asks for "added/removed, the delta-payload pattern, rather than full-state
/// dumps", and this is that pattern: the arrays, the truncation flag and the true total, with
/// the cap decided by `ironauth_store::membership_change` so no producer re-derives it.
///
/// It carries MEMBERSHIP ids, and says so in its field names. A group binding binds a
/// membership rather than a user, which is also what the per-member events above carry.
pub(crate) fn group_membership_delta_event(
    state: &ScimState,
    scope: Scope,
    group: &str,
    organization: &str,
    added: Vec<String>,
    removed: Vec<String>,
) -> Option<OwnedDomainEvent> {
    let change = ironauth_store::membership_change(added, removed);
    let mut payload = ironauth_store::membership_delta_payload(
        &change,
        "added_membership_ids",
        "removed_membership_ids",
    );
    payload["org_group_id"] = serde_json::json!(group);
    payload["organization_id"] = serde_json::json!(organization);
    envelope_for(
        state,
        scope,
        GROUP_MEMBERSHIP_CHANGED,
        group,
        &payload,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        GROUP_MEMBER_ADDED, GROUP_MEMBER_REMOVED, GROUP_MEMBERSHIP_CHANGED, USER_DEACTIVATED,
        USER_DEPROVISIONED, USER_STATE_CHANGED,
    };

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
        for wire in [
            USER_DEPROVISIONED,
            USER_DEACTIVATED,
            USER_STATE_CHANGED,
            GROUP_MEMBER_ADDED,
            GROUP_MEMBER_REMOVED,
            GROUP_MEMBERSHIP_CHANGED,
        ] {
            assert!(
                ironauth_store::event_catalog::registered(wire).is_some(),
                "{wire} is emitted by this crate and is not in the event catalog"
            );
        }
    }
}
