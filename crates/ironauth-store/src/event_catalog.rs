// SPDX-License-Identifier: MIT OR Apache-2.0

//! The typed, versioned event catalog (issue #108).
//!
//! # The catalog is the EVENT vocabulary, which is not the audit vocabulary
//!
//! The first version of this module derived the registry from `Action::as_str`, the audit
//! action list, and that was WRONG in a way only the delivery path could show: the audit
//! action is `user.create` and the event on the wire is `user.created`. Wiring catalog
//! validation into the webhook fan-out turned every real delivery red, which is how the
//! mistake surfaced.
//!
//! They are different vocabularies on purpose, and the distinction is the same one
//! [`crate::identity_fact`] draws. An audit action records what an ACTOR DID
//! (`operator X created a user`). An event records what BECAME TRUE (`a user now exists`).
//! A consumer wants the second, and deriving one from the other means inventing a mapping
//! nobody validated.
//!
//! So the registry is the list of types PRODUCERS actually emit, declared here beside their
//! schemas. That makes the count small and honest rather than large and fictional: issue
//! #108 asks for 100+ types, and reaching it means writing ~100 producers, not renaming an
//! audit list.
//!
//! # What a registered event promises
//!
//! Every type carries a payload schema version and a JSON Schema naming its fields. There
//! are no placeholders here: a type is in this registry because something emits it, and
//! anything that emits an event knows what it puts in the payload.
//!
//! # Versioning
//!
//! Additive changes extend a version; a breaking change mints a new one. The committed
//! artifact (`docs/events/catalog.json`) is what makes that enforceable: a schema edited
//! under an unchanged version shows up as a diff in a file a reviewer reads, and the
//! freshness gate refuses the commit until somebody looks.

use serde_json::{Value, json};

use crate::trait_schema::TraitSchema;

/// The envelope every event carries, on the push path and the pull path alike (issue #108).
///
/// A consumer validates THIS before it looks at the payload, so a malformed envelope is a
/// transport problem it can report rather than a payload problem it cannot parse.
#[must_use]
pub fn envelope_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "type": {"type": "string", "minLength": 1},
            "payload_schema_version": {"type": "integer"},
            "occurred_at_unix_ms": {"type": "integer"},
            "tenant_id": {"type": "string", "minLength": 1},
            "environment_id": {"type": "string", "minLength": 1},
            "payload": {"type": "object"}
        },
        "required": [
            "id",
            "type",
            "payload_schema_version",
            "occurred_at_unix_ms",
            "tenant_id",
            "environment_id",
            "payload"
        ]
    })
}

/// Every event type a producer emits, with its payload contract.
///
/// `(wire type, payload version, payload JSON Schema)`.
///
/// Every entry here has a PRODUCER. A registry entry for an event no producer sends is a
/// contract a consumer would wait on forever, which is the same fiction as an invented
/// payload schema, so nothing is listed until something emits it.
///
/// `user.deleted` and `user.updated` were both in that state -- subscription filter strings
/// in the webhook surface that nothing emitted, so an operator could subscribe and wait
/// forever. They are here now because the management delete and the management PATCH emit
/// them, not because the filter strings existed.
///
/// Adding a producer means adding a row here in the same change. The fan-out validates every
/// envelope against this registry and REFUSES an unregistered type permanently, so a new
/// event cannot reach the wire uncatalogued: the enforcement is the delivery path itself.
const REGISTERED: &[(&str, u32, &str)] = &[
    (
        "user.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "state"]
        }"#,
    ),
    (
        // Carries the FIRST ENVIRONMENT alongside the tenant, because creating a tenant
        // creates one in the same transaction and the management API returns both
        // (`TenantCreated`). A receiver told only the tenant id would have to go and ask
        // which environment to talk to, and the answer already exists here.
        "tenant.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1},
                "environment_id": {"type": "string", "minLength": 1},
                "display_name": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id", "environment_id", "display_name"]
        }"#,
    ),
    (
        // A brand asset is addressed by (brand slug, KIND) -- there is one logo per kind per
        // brand -- so both are needed to say WHICH asset went. A receiver mirroring the
        // hosted pages has to know whether the favicon or the logo disappeared; either alone
        // identifies nothing.
        // SET, not "created" or "updated": the write is an UPSERT (one asset per brand and
        // kind), so a consumer cannot be told which it was without the store reading the row
        // back first, and a receiver acts identically either way -- refetch the asset.
        //
        // The sha256 is the point of carrying anything beyond the ids: it lets a consumer
        // decide whether the bytes it already cached are stale WITHOUT refetching them. The
        // BYTES themselves are never on the wire; a webhook is not a CDN, and an image on
        // every subscriber's queue would dwarf every other event in the system.
        "brand_asset.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "brand_id": {"type": "string", "minLength": 1},
                "brand_slug": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1},
                "sha256": {"type": "string", "minLength": 1}
            },
            "required": ["brand_id", "brand_slug", "kind", "sha256"]
        }"#,
    ),
    (
        "brand_asset.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "brand_id": {"type": "string", "minLength": 1},
                "brand_slug": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1}
            },
            "required": ["brand_id", "brand_slug", "kind"]
        }"#,
    ),
    (
        // The NAME is the payload, because a variable is addressed by name everywhere -- in
        // the config that reads it and in the operator's head. There is no separate id to
        // fall back on.
        //
        // The VALUE is deliberately absent, and that is a rule rather than an omission: a
        // variable may hold anything an operator put there, and an event that echoed removed
        // values would be a channel for exfiltrating configuration by deleting it.
        // The NAME and nothing else, mirroring the delete -- and emphatically NOT the VALUE.
        // A variable is not a secret by TYPE, but an operator's choice to put something in a
        // variable rather than a secret is not a promise that every webhook subscriber may
        // read it. The name tells a consumer what to refetch through the authorized surface,
        // which is the same answer the delete gives.
        // THE NAME ONLY, and here that is not a judgement call at all: the value is a SECRET,
        // sealed at rest, and the management read surface will not return it either. An event
        // is a wider audience than that surface.
        //
        // Nothing derived from the value goes on the wire either -- no digest, no length, no
        // prefix. A digest of a low-entropy secret is guessable, and a length narrows a search;
        // the name is what tells a consumer which reference to re-resolve.
        "environment_secret.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["name"]
        }"#,
    ),
    (
        // As `environment_secret.set`: the name, and nothing that was ever the value.
        "environment_secret.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["name"]
        }"#,
    ),
    (
        "environment_variable.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["name"]
        }"#,
    ),
    (
        "environment_variable.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["name"]
        }"#,
    ),
    (
        // The self-referential one, and the reason it is safe: the fan-out lists the LIVE
        // endpoints after this transaction commits, so the removed endpoint is already gone
        // and never receives its own removal. The other endpoints do, which is the point --
        // a delivery topology changing under them is exactly what they want told.
        // The id and the URL. The URL is the endpoint's identity to an operator -- it is what
        // they recognise in a console and what they would check against their own
        // infrastructure -- and it is not a secret: the operator supplied it.
        //
        // NEVER the signing secret, and this type is the sharpest case of that rule in the
        // registry: the secret it would leak is the one that authenticates the very deliveries
        // this event travels on. A subscriber holding it could forge deliveries to that
        // endpoint.
        "webhook_endpoint.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1},
                "url": {"type": "string", "minLength": 1}
            },
            "required": ["webhook_endpoint_id", "url"]
        }"#,
    ),
    (
        // PAUSED and RESUMED as one type with a state, rather than two types. Unlike the
        // create/update pairs elsewhere in this registry, these are the SAME transition in two
        // directions over one boolean, and a consumer mirroring "is this endpoint delivering"
        // wants one subscription with a field to read, not two subscriptions to correlate.
        "webhook_endpoint.active_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1},
                "active": {"type": "boolean"}
            },
            "required": ["webhook_endpoint_id", "active"]
        }"#,
    ),
    (
        // THE ID ONLY. A rotation's whole content is a NEW SECRET, and that is precisely what
        // may not travel -- so what remains to say is that the endpoint's signing material
        // changed and an operator should expect the new key. The overlap window is not carried
        // either: it is a deployment policy a subscriber cannot act on and would only invite
        // treating this event as the authority on when the old secret dies.
        "webhook_endpoint.secret_rotated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1}
            },
            "required": ["webhook_endpoint_id"]
        }"#,
    ),
    (
        // The SUBSCRIPTION itself, because that is the fact: which types this endpoint asked
        // for. `event_types` is absent when the endpoint subscribes to EVERYTHING, mirroring
        // the column (NULL means no filter) rather than inventing an empty-list encoding that
        // would collide with "subscribed to nothing" -- a state the management surface
        // refuses.
        "webhook_endpoint.subscription_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1},
                "event_types": {"type": "array", "items": {"type": "string", "minLength": 1}}
            },
            "required": ["webhook_endpoint_id"]
        }"#,
    ),
    (
        // An operator ASKED for a replay; the deliveries themselves are the answer. Carrying
        // the request means a receiver can explain a burst of redeliveries it is about to see
        // rather than mistaking it for a live spike.
        "webhook_endpoint.replay_requested",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1}
            },
            "required": ["webhook_endpoint_id"]
        }"#,
    ),
    (
        "webhook_endpoint.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "webhook_endpoint_id": {"type": "string", "minLength": 1}
            },
            "required": ["webhook_endpoint_id"]
        }"#,
    ),
    (
        // The WIDEST narrowing in the registry. Deleting a permission removes it from every
        // role that referenced it at once -- one row, and everybody who held it through any
        // role loses it. A receiver mirroring access has more to undo here than for any other
        // event, which is why the slug travels: that is what a policy is written against.
        // The id and the SLUG, mirroring the delete: a permission is referenced by slug in
        // role grants and in an application's own authorization code, so an event carrying
        // only the id would make a receiver resolve the name before it could act.
        "permission.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "permission_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["permission_id", "slug"]
        }"#,
    ),
    (
        // Its own type: an update changes the DISPLAY of an existing permission and never its
        // slug, so a consumer that treated this as a create would invent a permission its
        // authorization model does not have.
        "permission.updated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "permission_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["permission_id", "slug"]
        }"#,
    ),
    (
        "permission.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "permission_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["permission_id", "slug"]
        }"#,
    ),
    (
        // Deleting a role removes whatever it granted from every member who held it, so this
        // is a PERMISSION change and a NARROWING one. A receiver mirroring access must not
        // learn about it late: the window between the delete and the reconcile is a window
        // where it still believes people can do things they no longer can.
        //
        // The organization travels with it because a role is org-scoped and a receiver
        // mirrors access per organization.
        // The role AND its organization, mirroring the delete: an org role is scoped to one
        // organization, and a receiver maintaining a per-organization view cannot file the
        // event without knowing which one.
        // THE MEMBERSHIP, ITS ORGANIZATION AND ITS USER, because a membership is a JOIN and a
        // consumer cannot act on it without both ends. This is the event an integrator most
        // often wires to provisioning: someone gained access to an organization.
        //
        // No role and no traits: a membership's role is changed through its own surface and
        // announced there, so folding it in here would make this event go stale the moment a
        // role moves without the membership changing.
        "organization.member_added",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "membership_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["membership_id", "organization_id", "user_id"]
        }"#,
    ),
    (
        // The mirror, and the one an integrator DEPROVISIONS on. Both ends again: a receiver
        // revoking downstream access needs to know whose access, to what.
        "organization.member_removed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "membership_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["membership_id", "organization_id", "user_id"]
        }"#,
    ),
    (
        // FOUR types rather than one pair with a nullable holder. A grant to a GROUP and a
        // grant to a MEMBER reach different downstream systems, and a pair distinguished by
        // "which id is present" is the same presence-ambiguity trap the subscription payload
        // avoids: a consumer that forgot to branch would apply a group grant to one person.
        // ORG GROUP lifecycle. The group AND its organization on every one, for the reason the
        // role types carry it: a group is scoped to one organization and a receiver keeping a
        // per-organization view cannot file the event without knowing which.
        // THE SESSION AND THE CAUSE, and deliberately NOT the user -- which is a constraint
        // the producer has rather than a preference. The revoke handler performs no pre-read
        // by design: "a revoke is idempotent over the session itself, so an absent session is
        // deliberately a 200 rather than a refusal". Nothing there knows whose session it was
        // when the envelope must be built, and adding a read to find out would reintroduce
        // exactly the refusal that comment rules out.
        //
        // A consumer that needs the subject resolves the session id, which it must be able to
        // do anyway to act on the revocation.
        //
        // The CAUSE is carried because revocations are not alike: an operator ending a session
        // and a session ended by a policy fence are the same row change and very different
        // facts to a SIEM. It is the store's own `SessionEndCause`, rendered, so the wire
        // cannot disagree with the audit row.
        //
        // NO SESSION TOKEN and nothing derived from one. A session id is an opaque handle the
        // holder already presented; the token is a credential.
        // THE USER, not the sessions. Unlike the bulk revoke -- where the caller supplies the
        // session ids and can build one envelope each -- this call supplies only the SUBJECT,
        // and the store discovers which sessions were live inside its own UPDATE. Nothing
        // knows them when the envelope must be built.
        //
        // It is also the better fact. "Every session of this user is gone" is what a receiver
        // acts on: it tears down everything for that subject, which it can do without an
        // enumeration it would otherwise have to reconcile against its own view.
        // The user AND the external id, because the whole content of the fact is the
        // CORRESPONDENCE: a receiver reconciling against an upstream directory needs both
        // sides or it cannot update its mapping.
        //
        // The external id is the OPERATOR'S OWN identifier for this person, supplied through
        // the management API -- not a credential and not a secret. Withholding it would make
        // the event unusable for the one job it exists to do.
        // The user and the identifier's ROW ID and TYPE -- and never the identifier VALUE.
        //
        // An identifier is an email address or a phone number: PII, sealed at rest, and the
        // reason this store keeps blind indexes rather than plaintext columns. A webhook is a
        // wider audience than the management read surface, so the same refusal holds. The
        // TYPE is carried because "an email was added" and "a phone was added" are different
        // facts to a receiver deciding whether to re-verify.
        // A CONFIG-PLANE recompute, not a per-user write: applying a uniqueness mode
        // recomputes the discriminator on EVERY identifier in the environment at once. There
        // is no single subject to name, and one event per affected row would be a storm that
        // says less than this one line does.
        //
        // The MODE is the payload, because a receiver mirroring identity policy needs to know
        // which rule now holds -- whether an address may repeat across organizations.
        "environment.identifier_uniqueness_applied",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mode": {"type": "string", "minLength": 1}
            },
            "required": ["mode"]
        }"#,
    ),
    (
        "user.identifier_added",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "identifier_id": {"type": "string", "minLength": 1},
                "identifier_type": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "identifier_id", "identifier_type"]
        }"#,
    ),
    (
        // The row id only, beside the user: the remove is given the id, not the value, and the
        // value would not belong on the wire even if it had it.
        "user.identifier_removed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "identifier_id": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "identifier_id"]
        }"#,
    ),
    (
        "user.external_id_linked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "external_id": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "external_id"]
        }"#,
    ),
    (
        // THE USER ONLY. The unlink is given just the user -- the store clears whatever was
        // there -- so nothing knows the outgoing external id when the envelope is built,
        // exactly as with `organization.default_role_cleared`. "This user no longer
        // corresponds to anything upstream" is also the whole of what a receiver acts on.
        "user.external_id_unlinked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["user_id"]
        }"#,
    ),
    (
        "user.sessions_revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["user_id"]
        }"#,
    ),
    (
        "session.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "session_id": {"type": "string", "minLength": 1},
                "cause": {"type": "string", "minLength": 1}
            },
            "required": ["session_id", "cause"]
        }"#,
    ),
    (
        "org_group.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id"]
        }"#,
    ),
    (
        // Display only, like `org_role.updated`: the slug and the parent are changed
        // elsewhere and announced by their own types.
        "org_group.updated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id"]
        }"#,
    ),
    (
        // ITS OWN TYPE, and the one with real consequences: reparenting moves a subtree, so
        // every role a group INHERITS can change without any grant being touched. A consumer
        // recomputing effective permissions must act on this, and would not if it were folded
        // into `org_group.updated` beside a display-name edit.
        //
        // `parent_org_group_id` is ABSENT when the group becomes a root, mirroring the column
        // and matching the subscription payload's rule: no invented sentinel.
        "org_group.reparented",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "parent_org_group_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id"]
        }"#,
    ),
    (
        "org_group.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id"]
        }"#,
    ),
    (
        // Group MEMBERSHIP, the pair an integrator provisions and deprovisions on, carrying
        // both ends of the join exactly as the organization membership types do.
        "org_group.member_added",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "membership_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id", "membership_id"]
        }"#,
    ),
    (
        "org_group.member_removed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "membership_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_group_id", "organization_id", "membership_id"]
        }"#,
    ),
    (
        "org_role.assigned_to_group",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "group_id": {"type": "string", "minLength": 1}
            },
            "required": ["assignment_id", "organization_id", "org_role_id", "group_id"]
        }"#,
    ),
    (
        // FOUR types rather than one pair with a nullable holder. A grant to a GROUP and a
        // grant to a MEMBER reach different downstream systems, and a pair distinguished by
        // "which id is present" is the same presence-ambiguity trap the subscription payload
        // avoids: a consumer that forgot to branch would apply a group grant to one person.
        "org_role.unassigned_from_group",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "group_id": {"type": "string", "minLength": 1}
            },
            "required": ["assignment_id", "organization_id", "org_role_id", "group_id"]
        }"#,
    ),
    (
        // FOUR types rather than one pair with a nullable holder. A grant to a GROUP and a
        // grant to a MEMBER reach different downstream systems, and a pair distinguished by
        // "which id is present" is the same presence-ambiguity trap the subscription payload
        // avoids: a consumer that forgot to branch would apply a group grant to one person.
        "org_role.assigned_to_member",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "membership_id": {"type": "string", "minLength": 1}
            },
            "required": ["assignment_id", "organization_id", "org_role_id", "membership_id"]
        }"#,
    ),
    (
        // FOUR types rather than one pair with a nullable holder. A grant to a GROUP and a
        // grant to a MEMBER reach different downstream systems, and a pair distinguished by
        // "which id is present" is the same presence-ambiguity trap the subscription payload
        // avoids: a consumer that forgot to branch would apply a group grant to one person.
        "org_role.unassigned_from_member",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "membership_id": {"type": "string", "minLength": 1}
            },
            "required": ["assignment_id", "organization_id", "org_role_id", "membership_id"]
        }"#,
    ),
    (
        "org_role.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_role_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_role_id", "organization_id"]
        }"#,
    ),
    (
        // Its own type: an update changes the DISPLAY of an existing role and never its slug
        // or its grants, so a consumer treating it as a create would invent a role that the
        // organization's authorization model does not contain.
        "org_role.updated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_role_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_role_id", "organization_id"]
        }"#,
    ),
    (
        // An ORGANIZATION event, not an `org_role.updated`. What changed is WHICH role the
        // organization hands to new members, not anything about the role itself -- the role's
        // slug, display and grants are untouched. A consumer syncing an organization's
        // onboarding policy watches this; one syncing the role catalogue does not.
        // ONE type carrying the new STATE, not an `enabled` and a `disabled` -- the same
        // shape as `webhook_endpoint.active_changed` and for the same reason: these are the
        // same transition in two directions over one value, and a consumer mirroring "is this
        // organization serving" wants one subscription with a field to read.
        //
        // The handler already refuses to let the two disagree ("enable and disable must not
        // disagree about whose event this is"), and one type makes that structural.
        "organization.state_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "state"]
        }"#,
    ),
    (
        "organization.default_role_set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "org_role_id"]
        }"#,
    ),
    (
        // THE ORGANIZATION ONLY, and the omission is forced rather than chosen: `clear_default`
        // discovers WHICH role was the default from its own RETURNING clause, so the producer
        // does not know it when the envelope has to be built. Naming the ex-default would mean
        // either a second read (racy) or building the event in the store (which no other
        // producer does).
        //
        // It is also sufficient. The fact is that this organization now has NO default role,
        // and a consumer syncing onboarding policy acts on that alone; which role it used to
        // be is in the audit trail.
        "organization.default_role_cleared",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id"]
        }"#,
    ),
    (
        "org_role.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_role_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["org_role_id", "organization_id"]
        }"#,
    ),
    (
        // An admin pre-authorization lets a client SKIP the consent screen. Revoking it means
        // the next authorize prompts instead -- a user-visible behaviour change, and the
        // narrowing of a standing grant, which is what makes it worth announcing.
        //
        // The client id rides along because the grant is per-client and that is what an
        // operator revoked; the grant's own id is an internal handle.
        "admin_consent.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_admin_grant_id": {"type": "string", "minLength": 1},
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["client_admin_grant_id", "client_id"]
        }"#,
    ),
    (
        // Removing a locale bundle changes what language a user is addressed in: the hosted
        // pages and the messages fall back to the default. The TAG is what carries that
        // meaning -- "de-DE went away" is actionable, an opaque bundle id is not -- so it
        // rides along and the handler reads it before the row goes.
        // THE TAG ONLY, and deliberately NOT the bundle id, which the delete does carry.
        //
        // `set` is an UPSERT and the store reuses the EXISTING row's id when the tag is
        // already present, minting the caller's id only on a first write. So the id the
        // caller has in hand is the stored id only sometimes, and an event built from it
        // would name a row that does not exist on every overwrite. The tag is how a bundle is
        // addressed everywhere else, it is stable across the upsert, and it is what a
        // consumer refetches by.
        "locale_bundle.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tag": {"type": "string", "minLength": 1}
            },
            "required": ["tag"]
        }"#,
    ),
    (
        "locale_bundle.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "locale_bundle_id": {"type": "string", "minLength": 1},
                "tag": {"type": "string", "minLength": 1}
            },
            "required": ["locale_bundle_id", "tag"]
        }"#,
    ),
    (
        // A signup form governs what a self-service REGISTRATION collects and requires, so
        // removing one changes who can sign up and with what. The client id rides along
        // because a signup form is per-client and that is how an operator refers to it.
        // THE CLIENT ONLY, for the reason on `locale_bundle.set`: the write is an upsert
        // keyed on the client, the store reuses the existing row's id, and the caller-minted
        // id is the stored one only on a first write. The client is the stable address.
        "signup_form.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["client_id"]
        }"#,
    ),
    (
        "signup_form.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "signup_form_id": {"type": "string", "minLength": 1},
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["signup_form_id", "client_id"]
        }"#,
    ),
    (
        // The DEPROVISIONING event. A state that ends sessions kills every live one in the
        // same transaction, so downstream systems act on this one: it is the notice that an
        // account stopped being able to log in.
        //
        // `state` is the destination only. The FROM state is deliberately absent: this write
        // re-checks `state = from` inside the transaction, so an event carrying a transition
        // would be asserting a pair the receiver cannot verify and does not need -- what it
        // acts on is where the account ended up.
        //
        // `hard_kill` rides along because it changes what the change DID: it decides whether
        // offline refresh families were revoked too, and a receiver cannot infer that later.
        "user.state_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1},
                "hard_kill": {"type": "boolean"}
            },
            "required": ["user_id", "state", "hard_kill"]
        }"#,
    ),
    (
        // A RESEND invalidates the prior token and issues a fresh one, so the news is that
        // any token a holder already has stopped working. That is why it is its own type and
        // not a second `invitation.created`: the invitation did not begin, it was reissued,
        // and a consumer counting creates would double-count one invitation.
        //
        // NO TOKEN and no digest, for the reason on the create: the fresh token is live at
        // exactly this moment, and a subscriber holding it could accept as the invitee.
        "invitation.resent",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "invitation_id": {"type": "string", "minLength": 1}
            },
            "required": ["invitation_id"]
        }"#,
    ),
    (
        // The INVITATION and the USER it was minted for, because the joined create makes
        // both in one transaction and a consumer that saw only the invitation could not tell
        // which pending account it belongs to without a second read.
        //
        // NO TOKEN, for the reason on `invitation.revoked`: the token is the credential, and
        // the create is exactly when it is still live. A subscriber that received it could
        // accept the invitation as the invitee.
        "invitation.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "invitation_id": {"type": "string", "minLength": 1},
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["invitation_id", "user_id"]
        }"#,
    ),
    (
        // REVOKED, not "deleted": the invitation row survives as a tombstone in the
        // `revoked` state, and a receiver treating this as a row deletion would drop the
        // record an operator needs to answer "who was invited, and what became of it".
        //
        // NO TOKEN and no digest, ever. The whole point of a revoke is that the token can no
        // longer be redeemed; putting any part of it on a webhook would hand every subscriber
        // material about a credential, for an event whose only news is that it stopped
        // working. The id correlates this with the invitation that was created.
        //
        // The event inherits the revoke's own guard: the write matches only a PENDING row, so
        // a repeat revoke is `NotFound` and emits nothing. A receiver counting revocations
        // cannot see two for one invitation because a client retried.
        "invitation.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "invitation_id": {"type": "string", "minLength": 1}
            },
            "required": ["invitation_id"]
        }"#,
    ),
    (
        // The id and the OWNER, because an api key is the same credential kind under three
        // different owners (user, service account, organization) and a consumer routing on
        // "who gained a credential" cannot get that from the id alone.
        //
        // NO KEY MATERIAL and no digest: the digest verifies exactly as well as the key does,
        // so putting it on the wire that announces the credential exists would BE the leak.
        "api_key.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "api_key_id": {"type": "string", "minLength": 1},
                "owner_kind": {"type": "string", "minLength": 1}
            },
            "required": ["api_key_id", "owner_kind"]
        }"#,
    ),
    (
        // ONE type naming BOTH ids, not a `created` plus a `revoked`.
        //
        // A rotation is ONE transaction (the store's `rotate`), and that is the whole point:
        // exposing it as create-then-revoke would hand back the window where both keys are
        // live, which is the failure a rotation performed to contain a leak exists to
        // prevent. Two events would recreate that fiction on the wire -- a consumer could
        // not tell a real rotation from an unrelated create that happened near a revoke, and
        // would have to infer the pairing from timing.
        //
        // Same reasoning as `invitation.resent`: the credential was not born and it did not
        // merely die, it was REPLACED, and a consumer counting creates or revocations would
        // otherwise double-count one operation.
        "api_key.rotated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "revoked_api_key_id": {"type": "string", "minLength": 1},
                "created_api_key_id": {"type": "string", "minLength": 1}
            },
            "required": ["revoked_api_key_id", "created_api_key_id"]
        }"#,
    ),
    (
        // Emitted at most ONCE per credential. The revocation is idempotent -- a retried
        // revoke changes nothing and audits nothing -- and the event inherits that, so a
        // receiver counting revocations never sees two for one key because a client retried.
        //
        // The id only, for the reason on `management_key.revoked`: nothing derived from the
        // secret belongs on the wire that announces it is dead.
        "api_key.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "api_key_id": {"type": "string", "minLength": 1}
            },
            "required": ["api_key_id"]
        }"#,
    ),
    (
        // REVOKED, not "deleted", because that is what happened: a management credential lost
        // its authority. The row survives as a tombstone, and a receiver that treated this as
        // a row deletion would garbage-collect audit references that must stay legible.
        //
        // No key material and no prefix: the id is enough to correlate, and anything derived
        // from the secret would put a fragment of a credential on a wire this event exists to
        // tell people to stop trusting.
        "management_key.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "management_key_id": {"type": "string", "minLength": 1}
            },
            "required": ["management_key_id"]
        }"#,
    ),
    (
        // Removing a connector changes WHO CAN LOG IN to this environment, which is why a
        // receiver wants it promptly rather than at the next reconcile. The SLUG rides along
        // with the id because that is what a connector is referenced by everywhere else --
        // in routing rules, in the federation URL, in an operator's own configuration -- so
        // an id alone would send the receiver looking it up in a row that no longer exists.
        // The id and the SLUG, mirroring the delete: the slug is how a connector is named in
        // configuration and in the federation URLs, so an event carrying only the id would
        // make a receiver look the name up to act on it.
        //
        // NEVER the definition and NEVER the client secret. A connector row holds an upstream
        // CREDENTIAL; the whole point of the secret-free read surface is that it does not
        // leave through the API, and a webhook is a wider audience than the API.
        "connector.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "connector_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["connector_id", "slug"]
        }"#,
    ),
    (
        // Its own type rather than a second `connector.created`: an update REPLACES the
        // upstream definition of a live federation, which is the change a receiver most needs
        // to distinguish -- a consumer counting new federations would otherwise count every
        // edit as a new one.
        //
        // Same payload, and the same prohibition: no definition, no client secret.
        "connector.updated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "connector_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["connector_id", "slug"]
        }"#,
    ),
    (
        "connector.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "connector_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["connector_id", "slug"]
        }"#,
    ),
    (
        // Deleting an environment FENCES its data plane: the same transaction flips
        // environment_states to suspended. So this event means "this environment stopped
        // serving", which is the fact a receiver acts on -- it is not merely a row change,
        // and every client of that environment is affected at once.
        "environment.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "environment_id": {"type": "string", "minLength": 1},
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["environment_id", "tenant_id"]
        }"#,
    ),
    (
        // A HARD delete, unlike the user and organization tombstones, so a receiver cannot
        // read the row back to confirm. That makes the event the only notice it gets, which
        // is why the payload carries the client_id and nothing that could go stale.
        "client.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["client_id"]
        }"#,
    ),
    (
        // The display name is carried because it is the whole of what a create decided that a
        // receiver cannot derive from the id. Everything else about a new organization is
        // either the id itself or scope, both already on the envelope.
        "organization.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "display_name": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "display_name"]
        }"#,
    ),
    (
        // No display name here: the delete is a soft tombstone and the receiver has had the
        // name since the create. Repeating it would invite a consumer to treat the delete as
        // the authoritative record of a name it may have since changed.
        "organization.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id"]
        }"#,
    ),
    (
        // `fields` names WHAT changed, because a PATCH may carry claims, traits, or both, and
        // a receiver that has to re-read the whole user to find out has gained nothing from
        // being told. It is a list rather than a single value for the same reason.
        //
        // One event per WRITE, not per request. The management PATCH runs claims and traits
        // as two separate audited transactions on purpose (they are different facts and an
        // operator reads them separately), and an event has to be transactional with the
        // write it announces -- so a combined patch emits two, each naming its own field. The
        // alternative, one event after both, cannot be transactional with either: if the
        // traits write failed after the claims write committed, no event would be emitted at
        // all and a real change would be silent.
        "user.updated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "fields": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "enum": ["claims", "traits"]}
                }
            },
            "required": ["user_id", "fields"]
        }"#,
    ),
    (
        // `hard_kill` rides the payload because it changes what the delete DID, not just
        // that it happened: a soft delete leaves the offline refresh families alive and a
        // hard kill revokes them. A receiver reconciling its own copy needs to tell those
        // apart, and it cannot ask afterwards -- the user reads as absent either way.
        "user.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "hard_kill": {"type": "boolean"}
            },
            "required": ["user_id", "hard_kill"]
        }"#,
    ),
];

/// Build the envelope a receiver is sent, stamping the version the REGISTRY declares for
/// `event_type`.
///
/// The version is looked up rather than passed, and that is the point of building it here:
/// the envelope and the schema it must validate against are now produced from one source, so
/// a producer cannot stamp a version the registry does not have. A hand-passed version is a
/// second declaration of the same fact, and the fan-out refuses a mismatch permanently --
/// which surfaces as an undeliverable event rather than a compile error.
///
/// Returns `None` for an unregistered type. That is not a convenience: a producer for a type
/// the registry does not know is exactly what the fan-out refuses, and failing here means the
/// write that would have announced it never happens.
#[must_use]
pub fn envelope(
    id: &str,
    event_type: &str,
    tenant_id: &str,
    environment_id: &str,
    occurred_at_unix_ms: i64,
    payload: &serde_json::Value,
) -> Option<serde_json::Value> {
    let version = registered(event_type)?.payload_version;
    Some(serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": version,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "tenant_id": tenant_id,
        "environment_id": environment_id,
        "payload": payload,
    }))
}

/// The number of event types issue #108 asks the catalog to reach before it closes.
///
/// Stated as a constant the tests read so the gap is a NUMBER somebody can see rather than a
/// sentence in an issue. Reaching it means writing producers; see the module note on why it
/// cannot be reached by renaming the audit list.
pub const TARGET_REGISTERED_TYPES: usize = 100;

/// One registered event type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEvent {
    /// The wire type, for example `user.create`.
    pub wire: String,
    /// The leading segment, for example `user`. The catalog groups by it.
    pub domain: String,
    /// The payload schema version this type currently emits.
    pub payload_version: u32,
    /// The payload JSON Schema, as text.
    pub payload_schema: String,
}

/// Every registered event type, sorted.
#[must_use]
pub fn event_types() -> Vec<String> {
    let mut out: Vec<String> = REGISTERED
        .iter()
        .map(|(wire, _, _)| (*wire).to_owned())
        .collect();
    out.sort_unstable();
    out
}

/// The full registry.
#[must_use]
pub fn registry() -> Vec<RegisteredEvent> {
    let mut out: Vec<RegisteredEvent> = REGISTERED
        .iter()
        .map(|(wire, version, schema)| RegisteredEvent {
            wire: (*wire).to_owned(),
            domain: wire
                .split_once('.')
                .map_or_else(|| (*wire).to_owned(), |(head, _)| head.to_owned()),
            payload_version: *version,
            payload_schema: (*schema).to_owned(),
        })
        .collect();
    out.sort_by(|a, b| a.wire.cmp(&b.wire));
    out
}

/// Look one type up.
#[must_use]
pub fn registered(wire: &str) -> Option<RegisteredEvent> {
    registry().into_iter().find(|entry| entry.wire == wire)
}

/// Why an envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// The envelope itself is malformed; the strings are JSON Pointer failures.
    Envelope(Vec<String>),
    /// The `type` names a type the registry does not carry. This is the check that makes
    /// "emitting an unregistered type fails the build" enforceable.
    UnregisteredType(String),
    /// The payload does not satisfy the registered schema for its type.
    Payload {
        /// The event type.
        wire: String,
        /// The JSON Pointer failures.
        failures: Vec<String>,
    },
    /// The envelope declares a payload version the registry does not emit.
    VersionMismatch {
        /// The event type.
        wire: String,
        /// What the envelope declared.
        declared: u32,
        /// What the registry says.
        registered: u32,
    },
}

/// Validate one envelope against the catalog: shape, then registration, then payload.
///
/// The order matters. A malformed envelope has no trustworthy `type`, so checking
/// registration first would report "unregistered type" for what is really a broken producer.
///
/// # Errors
///
/// [`CatalogError`] describing the first check that failed.
///
/// # Panics
///
/// If the envelope schema or a registered payload schema fails to compile. Both are
/// compile-time constants in this module and `every_registered_schema_compiles` pins them,
/// so reaching either panic means that test was deleted.
pub fn validate_event(envelope: &Value) -> Result<(), CatalogError> {
    let schema = TraitSchema::compile(&envelope_schema().to_string())
        .expect("the envelope schema is a compile-time constant and compiles");
    let failures = schema.validate(envelope);
    if !failures.is_empty() {
        return Err(CatalogError::Envelope(
            failures
                .iter()
                .map(|failure| format!("{}: {}", failure.pointer, failure.message))
                .collect(),
        ));
    }
    let wire = envelope
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(entry) = registered(&wire) else {
        return Err(CatalogError::UnregisteredType(wire));
    };
    let declared = envelope
        .get("payload_schema_version")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let declared = u32::try_from(declared).unwrap_or(u32::MAX);
    if declared != entry.payload_version {
        return Err(CatalogError::VersionMismatch {
            wire,
            declared,
            registered: entry.payload_version,
        });
    }
    let payload = envelope.get("payload").cloned().unwrap_or(json!({}));
    let payload_schema = TraitSchema::compile(&entry.payload_schema)
        .expect("a registered payload schema compiles; a test pins that");
    let failures = payload_schema.validate(&payload);
    if !failures.is_empty() {
        return Err(CatalogError::Payload {
            wire,
            failures: failures
                .iter()
                .map(|failure| format!("{}: {}", failure.pointer, failure.message))
                .collect(),
        });
    }
    Ok(())
}

/// The catalog as the committed artifact, for the docs generator and the freshness gate.
#[must_use]
pub fn catalog_document() -> Value {
    let entries: Vec<Value> = registry()
        .into_iter()
        .map(|entry| {
            json!({
                "type": entry.wire,
                "domain": entry.domain,
                "payload_schema_version": entry.payload_version,
                "payload_schema": serde_json::from_str::<Value>(&entry.payload_schema)
                    .unwrap_or(json!({})),
            })
        })
        .collect();
    json!({
        "envelope_schema": envelope_schema(),
        "event_types": entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is non-empty, its types are distinct, and the distance to issue #108's
    /// target is stated rather than implied.
    ///
    /// The gap is an assertion so it cannot be forgotten: 100+ types is reached by writing
    /// PRODUCERS, and this fails loudly the day somebody believes it was reached by
    /// renaming something.
    #[test]
    fn the_registry_is_non_empty_distinct_and_reports_its_distance_to_the_target() {
        let types = event_types();
        assert!(!types.is_empty(), "the registry is empty");
        let mut sorted = types.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            types.len(),
            "two event types share a wire string"
        );
        assert!(
            types.len() < TARGET_REGISTERED_TYPES,
            "the registry reached {} types, at or past issue #108's target of \
             {TARGET_REGISTERED_TYPES}. Raise or retire TARGET_REGISTERED_TYPES and say so \
             in the issue: the target is a reminder that the catalog is incomplete, and a \
             reminder nobody updates is a reminder that lies.",
            types.len()
        );
    }

    /// Every registered type is a dotted, `snake_case` token in the PAST TENSE.
    ///
    /// The past tense is the vocabulary rule that keeps this list from drifting back into
    /// the audit vocabulary, which is imperative (`user.create`). Asserted rather than
    /// documented, because that drift is the defect this module was born from.
    #[test]
    fn every_registered_type_is_a_dotted_past_tense_token() {
        for wire in event_types() {
            let (domain, rest) = wire
                .split_once('.')
                .unwrap_or_else(|| panic!("`{wire}` is not a dotted token"));
            assert!(
                !domain.is_empty() && !rest.is_empty(),
                "`{wire}` has an empty segment"
            );
            assert!(
                wire.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "`{wire}` is not a snake_case dotted token"
            );
            assert!(
                rest.ends_with("ed"),
                "`{wire}` is not past tense. An event records what BECAME TRUE; the \
                 imperative form is the AUDIT vocabulary, and conflating the two is the \
                 defect this rule exists to prevent."
            );
        }
    }

    /// Every registered payload schema COMPILES, and so does the envelope schema.
    ///
    /// `validate_event` expects both, and an uncompilable schema would turn every event of
    /// that type into a panic on the delivery path.
    #[test]
    fn every_registered_schema_compiles() {
        TraitSchema::compile(&envelope_schema().to_string()).expect("the envelope compiles");
        for entry in registry() {
            TraitSchema::compile(&entry.payload_schema).unwrap_or_else(|error| {
                panic!(
                    "the schema for `{}` does not compile: {error:?}",
                    entry.wire
                )
            });
        }
    }

    fn good_envelope() -> Value {
        json!({
            "id": "evt_1",
            "type": "user.created",
            "payload_schema_version": 1,
            "occurred_at_unix_ms": 1_700_000_000_000_i64,
            "tenant_id": "ten_1",
            "environment_id": "env_1",
            "payload": {"user_id": "usr_1", "state": "active"}
        })
    }

    /// A well-formed event validates.
    #[test]
    fn a_well_formed_event_validates() {
        assert_eq!(validate_event(&good_envelope()), Ok(()));
    }

    /// EVERY required envelope field is required, one at a time.
    ///
    /// Asserted per field rather than once, because a schema requiring only `id` would pass
    /// a single happy-path test while every other field went missing.
    #[test]
    fn removing_any_required_envelope_field_is_refused() {
        for field in [
            "id",
            "type",
            "payload_schema_version",
            "occurred_at_unix_ms",
            "tenant_id",
            "environment_id",
            "payload",
        ] {
            let mut envelope = good_envelope();
            envelope
                .as_object_mut()
                .expect("an object")
                .remove(field)
                .expect("the field was present");
            assert!(
                matches!(validate_event(&envelope), Err(CatalogError::Envelope(_))),
                "an envelope missing `{field}` was accepted"
            );
        }
    }

    /// An UNREGISTERED type is refused by name, which is what makes "emitting an
    /// unregistered event fails" enforceable at the delivery choke point.
    #[test]
    fn an_unregistered_event_type_is_refused() {
        let mut envelope = good_envelope();
        envelope["type"] = json!("user.invented_by_nobody");
        assert_eq!(
            validate_event(&envelope),
            Err(CatalogError::UnregisteredType(
                "user.invented_by_nobody".to_owned()
            ))
        );
    }

    /// An AUDIT action string is not an event type, and is refused as unregistered.
    ///
    /// The specific confusion that produced the first version of this module, pinned so it
    /// cannot come back quietly.
    #[test]
    fn an_audit_action_string_is_not_an_event_type() {
        let mut envelope = good_envelope();
        envelope["type"] = json!("user.create");
        assert!(
            matches!(
                validate_event(&envelope),
                Err(CatalogError::UnregisteredType(_))
            ),
            "`user.create` is the AUDIT vocabulary; the event is `user.created`"
        );
    }

    /// A payload that violates its registered schema is refused, naming the type.
    #[test]
    fn a_payload_violating_its_registered_schema_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload"] = json!({"user_id": "usr_1"});
        match validate_event(&envelope) {
            Err(CatalogError::Payload { wire, failures }) => {
                assert_eq!(wire, "user.created");
                assert!(!failures.is_empty(), "the refusal must say what failed");
            }
            other => panic!("expected a payload refusal, got {other:?}"),
        }
    }

    /// A version the registry does not emit is refused rather than validated against
    /// whatever schema is current: the versioning policy's enforcement point.
    #[test]
    fn a_declared_version_the_registry_does_not_emit_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload_schema_version"] = json!(2);
        assert_eq!(
            validate_event(&envelope),
            Err(CatalogError::VersionMismatch {
                wire: "user.created".to_owned(),
                declared: 2,
                registered: 1,
            })
        );
    }

    /// The catalog document carries every type and the envelope schema.
    #[test]
    fn the_catalog_document_carries_every_type_and_the_envelope() {
        let document = catalog_document();
        assert!(document.get("envelope_schema").is_some());
        let entries = document["event_types"].as_array().expect("an array");
        assert_eq!(entries.len(), registry().len());
        assert!(entries.iter().all(|entry| entry.get("type").is_some()));
    }
}
