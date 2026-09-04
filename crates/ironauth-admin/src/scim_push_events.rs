// SPDX-License-Identifier: MIT OR Apache-2.0

//! What one feed event means for an outbound SCIM connection (issue #137).
//!
//! # Why this is a separate module with its own suite
//!
//! Issue #137 says the outbound worker is "just another cursor-based event consumer", and the
//! honest reading of that is that the worker is two things bolted together: a LOOP that reads
//! pages and checkpoints, and a TRANSLATION from a domain event to a SCIM intent. The loop needs
//! a database and a downstream to test. The translation needs neither, and it is where the
//! interesting mistakes live, so it is separated to be tested exhaustively.
//!
//! # The mistake this module exists to prevent
//!
//! A translation written as a `match` over the event types somebody remembered is silently
//! incomplete: a `user.deprovisioned` nobody mapped falls to the wildcard, is ignored, and the
//! departure never reaches the downstream. Nothing fails, no error is logged, and the account
//! stays live. That is the same shape as the defect the merged client had, arriving from the
//! other end.
//!
//! So the wildcard is not trusted. [`intent_for`] is TOTAL over the event catalog, and
//! `every_catalogued_subject_event_is_classified` walks `ironauth_store::event_catalog` and
//! fails if any user or group event is neither mapped nor explicitly named as ignored. Adding an
//! event type to the catalog therefore breaks this crate's suite until somebody decides what it
//! means for outbound provisioning, which is the decision that would otherwise be skipped.

/// The SCIM collection a subject belongs to.
///
/// A re-export of [`ironauth_scim::ResourceType`] rather than a second enum. An earlier version
/// of this module declared its own `Collection { Users, Groups }`, which gave the same two-element
/// set three vocabularies in one repository: this one, `ResourceType` in the inbound half, and
/// `ScimPushResourceType` in the store. Two of them now agree by being the same type; the store's
/// stays separate because it is the spelling a database CHECK constrains, and a Rust enum that
/// travels into SQL is a different obligation from one that names a URL path.
pub use ironauth_scim::ResourceType as Collection;

/// The path a SCIM client addresses this collection at, with the leading slash the client builds.
///
/// [`Collection::as_str`] gives the bare SCIM spelling (`Users`), which is what a `ResourceRef`
/// and a schema URN use. The client's request paths carry the slash, and putting the join here
/// keeps that difference in one place rather than at every call site.
#[must_use]
pub fn collection_path(collection: Collection) -> &'static str {
    match collection {
        Collection::User => "/Users",
        Collection::Group => "/Groups",
    }
}

/// What the worker should do about one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushIntent {
    /// Push the subject's current state downstream, creating or updating as needed.
    Converge {
        /// Which SCIM collection.
        collection: Collection,
        /// IronAuth's own id for the subject.
        subject_id: String,
    },
    /// Remove the subject downstream, per the connection's deletion policy.
    Deprovision {
        /// Which SCIM collection.
        collection: Collection,
        /// IronAuth's own id for the subject.
        subject_id: String,
    },
    /// Nothing to push, and the reason is recorded rather than implied.
    Ignore(Ignored),
}

/// Why an event produces no SCIM request.
///
/// An enum rather than a bare `None` because "we decided this is irrelevant" and "we have never
/// heard of this" are different situations, and only the second one is a bug. A wildcard that
/// collapsed them is how an unmapped departure becomes silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignored {
    /// Catalogued, and deliberately not a provisioning signal: a sign-in, a session revocation,
    /// a token event. Pushing on these would send a write per login.
    NotAProvisioningSignal,
    /// Catalogued and about something other than a user or a group: a tenant, a client, a key.
    NotASubject,
    /// The payload did not carry the subject id its schema requires.
    ///
    /// Distinct from the two above because it is a DEFECT somewhere, not a decision here: the
    /// catalog validates envelopes on the way in, so a registered event missing a required
    /// property means the schema and the producer disagree. The worker records it rather than
    /// silently skipping, and rather than failing the whole page for one bad row.
    MalformedPayload,
}

/// Every catalogued event this module deliberately does not push on.
///
/// Listed rather than matched by prefix so that adding, say, `user.exported` to the catalog fails
/// `every_catalogued_subject_event_is_classified` instead of being swept into a pattern somebody
/// wrote for a different reason. The cost of the list is one line per decision; the cost of the
/// prefix is a departure that never reaches the downstream.
const NOT_A_PROVISIONING_SIGNAL: &[&str] = &[
    "user.signed_in",
    "user.sessions_revoked",
    "user.external_id_linked",
    "user.external_id_unlinked",
];

/// What one event means, given its catalogued type and its payload.
///
/// Total over the catalog: see the module header for why the wildcard is not trusted.
#[must_use]
pub fn intent_for(event_type: &str, payload: &serde_json::Value) -> PushIntent {
    let subject = |key: &str| payload.get(key).and_then(serde_json::Value::as_str);
    match event_type {
        // A USER'S STATE CHANGED, which includes being created. Converge sends the whole mapped
        // representation, so one intent covers create and update: the client decides which by
        // looking the subject up, which is also what makes a replay idempotent.
        "user.created"
        | "user.updated"
        | "user.state_changed"
        | "user.identifier_added"
        | "user.identifier_removed" => match subject("user_id") {
            Some(id) => PushIntent::Converge {
                collection: Collection::User,
                subject_id: id.to_owned(),
            },
            None => PushIntent::Ignore(Ignored::MalformedPayload),
        },
        // A DEPARTURE. All three mean the person should no longer be provisioned; what happens
        // downstream is the CONNECTION's deletion policy, not this decision, which is why they
        // collapse to one intent. `user.deactivated` is included deliberately: a deactivated
        // account that stays active downstream is the failure #137 exists to prevent.
        "user.deleted" | "user.deprovisioned" | "user.deactivated" => match subject("user_id") {
            Some(id) => PushIntent::Deprovision {
                collection: Collection::User,
                subject_id: id.to_owned(),
            },
            None => PushIntent::Ignore(Ignored::MalformedPayload),
        },
        // GROUP SHAPE OR MEMBERSHIP. A membership change is a converge of the GROUP, not of the
        // member: RFC 7643 section 4.2 puts `members` on the group, so the downstream write is a
        // group update either way.
        "org_group.created"
        | "org_group.updated"
        | "org_group.reparented"
        | "org_group.member_added"
        | "org_group.member_removed"
        | "org_group.membership_changed" => match subject("group_id") {
            Some(id) => PushIntent::Converge {
                collection: Collection::Group,
                subject_id: id.to_owned(),
            },
            None => PushIntent::Ignore(Ignored::MalformedPayload),
        },
        "org_group.deleted" => match subject("group_id") {
            Some(id) => PushIntent::Deprovision {
                collection: Collection::Group,
                subject_id: id.to_owned(),
            },
            None => PushIntent::Ignore(Ignored::MalformedPayload),
        },
        other if NOT_A_PROVISIONING_SIGNAL.contains(&other) => {
            PushIntent::Ignore(Ignored::NotAProvisioningSignal)
        }
        _ => PushIntent::Ignore(Ignored::NotASubject),
    }
}

/// Whether a subject is in this connection's scope, and what that means if it just left.
///
/// # Criterion 4
///
/// #137 asks that "out-of-scope users are never pushed, and a user leaving scope is deactivated
/// downstream per policy". Those are two different obligations and only the first is obvious.
/// A subject that is out of scope AND has no link was never provisioned, so there is nothing to
/// do. A subject that is out of scope but HAS a link was provisioned before and has since left:
/// silence would leave them live downstream for ever, so the departure has to be pushed.
///
/// Deciding that here, from the link's presence, is what makes "never pushed" and "deactivated on
/// leaving" the same rule rather than two that can drift apart.
#[must_use]
pub fn scope_decision(in_scope: bool, has_link: bool) -> ScopeDecision {
    match (in_scope, has_link) {
        (true, _) => ScopeDecision::Push,
        (false, true) => ScopeDecision::Withdraw,
        (false, false) => ScopeDecision::Skip,
    }
}

/// The outcome of [`scope_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    /// In scope: apply the intent.
    Push,
    /// Out of scope and previously provisioned: deprovision, whatever the intent said.
    Withdraw,
    /// Out of scope and never provisioned: nothing to do.
    Skip,
}
