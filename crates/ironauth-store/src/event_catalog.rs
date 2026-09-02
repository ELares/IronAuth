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
//! schemas. That makes the count honest rather than large and fictional: every entry cost a
//! producer, and none of it could have been reached by renaming the audit list.
//!
//! The count is no longer the measure, and this module no longer states one -- see the
//! retirement note on the constant that used to hold it. Coverage is measured against the
//! management ROUTER by `scripts/producer-coverage.py`, which is the direction that
//! matters: not how many types exist, but whether any write handler announces nothing.
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
        // `environment_id` is NOT here, and that is not a loosening of the guarantee: it is
        // enforced PER TYPE by `validate_event`, which requires it for every
        // environment-scoped type and forbids it for the tenant-scoped ones.
        //
        // Blanket-required was the old rule and it made tenant-scoped events inexpressible:
        // deleting a tenant fences ALL of its environments, so there is no one environment to
        // name, and the store picks the audit scope itself after the call begins. Dropping it
        // from the list wholesale would have been the wrong fix -- a consumer of the existing
        // twenty types decodes this field infallibly, and "sometimes absent" breaks it. Per
        // type, those twenty are unchanged.
        "required": [
            "id",
            "type",
            "payload_schema_version",
            "occurred_at_unix_ms",
            "tenant_id",
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
        // TENANT-SCOPED: no `environment_id` on the envelope. Deleting a tenant fences EVERY
        // one of its environments in the same transaction, so naming one would assert
        // something untrue about the rest -- and the store picks the audit scope itself (the
        // oldest environment) after the call begins, so a producer could not name the right
        // one even if there were one. This is the type the per-type envelope rule exists for.
        // TENANT-SCOPED, for the same reason as `tenant.deleted`: suspending fences EVERY one
        // of the tenant's environments in one transaction, so naming one would assert
        // something untrue about the rest.
        //
        // Its own type rather than a state field, and separate from the resume: a suspension
        // STOPS a tenant's data plane serving and a resume starts it again. A consumer that
        // read one as the other would fence a live tenant or serve a fenced one, and there is
        // no reading of a shared "state changed" that fails safe.
        "tenant.suspended",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id"]
        }"#,
    ),
    (
        // The reversing half. No data was lost by the suspension, so this is the announcement
        // that a consumer may resume trusting the tenant.
        "tenant.resumed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id"]
        }"#,
    ),
    (
        // The UNDELETE, inside the retention window. It carries no status, deliberately: a
        // restore commits the status the tenant HELD before it was deleted, which the store
        // resolves inside the write, so a producer naming one would be announcing a value it
        // could not know. A receiver reads the status back through the management surface,
        // which is the same answer the endpoint gives its caller.
        "tenant.restored",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id"]
        }"#,
    ),
    (
        // TERMINAL, and its own type for that reason above all. A purge crypto-shreds the
        // tenant's keys: there is no restore after it, and a consumer that read it as the
        // soft delete would wait out a retention window that will never end in a recovery.
        // This is the event that says "stop holding anything for this tenant".
        "tenant.purged",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id"]
        }"#,
    ),
    (
        "tenant.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id"]
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
        // A brand is what an end user SEES at the login surface, so a consumer mirroring
        // branding acts on the id and the slug and re-reads the rest: the tokens, the slots,
        // and the host pattern are a config document, not a fact, and putting a document on
        // the wire means every consumer has to version it.
        //
        // `is_default` DOES travel, because it is not part of that document: flipping it
        // changes which brand serves a request that matched no other, which is a behavioural
        // change a consumer cannot see by re-reading only the brand it was told about.
        "brand.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "brand_id": {"type": "string", "minLength": 1},
                "brand_slug": {"type": "string", "minLength": 1},
                "is_default": {"type": "boolean"}
            },
            "required": ["brand_id", "brand_slug", "is_default"]
        }"#,
    ),
    (
        // The delete takes the brand's ASSETS with it, so a consumer that read this as a
        // brand-only removal would keep serving logos from a brand that no longer exists.
        "brand.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "brand_id": {"type": "string", "minLength": 1},
                "brand_slug": {"type": "string", "minLength": 1}
            },
            "required": ["brand_id", "brand_slug"]
        }"#,
    ),
    (
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
        // THE DELTA-BEARING FORM (issue #107's criterion, issue #108's registry). It exists
        // beside the per-member types rather than replacing them, because they answer
        // different questions: `member_added` says WHO, once, and this says WHAT THE SET DID.
        //
        // Arrays and a cap, because full-state group dumps melt at enterprise group sizes.
        // The cap is on the TOTAL ids in the event, not per array -- a per-array cap lets one
        // event carry twice the documented limit, which gets discovered by a consumer's
        // allocator rather than by a reviewer.
        //
        // `truncated` is REQUIRED, not optional, and that is the whole safety property. A
        // truncated delta applied as though it were complete CORRUPTS the consumer: it
        // believes the members it was not sent are unchanged, and they are not. Making the
        // flag required means a consumer cannot read the arrays without having seen it, and
        // an omitted flag is a schema violation refused at the fan-out rather than a default
        // that silently reads as "complete".
        //
        // `total` rides along on every event, so a consumer that truncated can log exactly
        // how much it missed, and reconciles by re-reading the membership through the
        // management API -- the path `membership_reconcile.rs` measures to exhaustion.
        "organization.membership_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "added_user_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                "removed_user_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                "truncated": {"type": "boolean"},
                "total": {"type": "integer", "minimum": 0}
            },
            "required": [
                "organization_id",
                "added_user_ids",
                "removed_user_ids",
                "truncated",
                "total"
            ]
        }"#,
    ),
    (
        // The GROUP twin, same contract. Groups are where the cap actually bites: an
        // enterprise group is the thing with tens of thousands of members, which is why
        // issue #107 named group dumps as the failure mode.
        "org_group.membership_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "org_group_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "added_user_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                "removed_user_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                "truncated": {"type": "boolean"},
                "total": {"type": "integer", "minimum": 0}
            },
            "required": [
                "org_group_id",
                "organization_id",
                "added_user_ids",
                "removed_user_ids",
                "truncated",
                "total"
            ]
        }"#,
    ),
    (
        // A MACHINE IDENTITY joining an organization (issue #126).
        //
        // A separate type rather than a `user_id`-or-`service_account_id` variant of
        // `organization.member_added`: that schema makes `user_id` REQUIRED, and relaxing a
        // required property is breaking for every consumer already decoding it. A consumer
        // that wants both subscribes to both; one that only ever expected people keeps
        // working and does not silently start receiving members it cannot render.
        "organization.service_account_added",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "membership_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "service_account_id": {"type": "string", "minLength": 1}
            },
            "required": ["membership_id", "organization_id", "service_account_id"]
        }"#,
    ),
    (
        // The mirror, and the one an integrator DEPROVISIONS on. Both ends, for the reason
        // the user pair records: a receiver that learns only about joins accumulates
        // authority it can never take away.
        "organization.service_account_removed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "membership_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "service_account_id": {"type": "string", "minLength": 1}
            },
            "required": ["membership_id", "organization_id", "service_account_id"]
        }"#,
    ),
    (
        // An AGENT PRINCIPAL registered (issue #130). Carries all three facts an integrator
        // needs to act on it: the agent, the organization it acts inside, and the user it
        // acts FOR. A registration event naming only the agent would tell a SIEM that
        // something appeared and nothing about whose authority it carries.
        "agent.registered",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "agent_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "linked_user_id": {"type": "string", "minLength": 1}
            },
            "required": ["agent_id", "organization_id", "linked_user_id"]
        }"#,
    ),
    (
        // And the lifecycle change, which is the one an incident responder subscribes to.
        // `state` carries the resulting value rather than only the fact of a change, because
        // "an agent was suspended" and "an agent was un-suspended" are different alerts.
        "agent.state_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "agent_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1}
            },
            "required": ["agent_id", "organization_id", "state"]
        }"#,
    ),
    (
        // An approver DECIDED a held action (issue #132, criterion 4).
        //
        // Carries WHO decided, which is the question an integrator watching this actually
        // asks. An earlier version of this comment claimed it carried "what was agreed to"
        // and the schema had no such property, with `additionalProperties: false` making one
        // unaddable without a version bump -- so the sentence described an event that could
        // not exist. What was agreed to stays out deliberately: it is the approver's narrowed
        // authorization details, it can be large, and it is on the audit row and in the
        // exchange response for the parties that need it.
        //
        // Never the credential, which an approval never touches.
        "agent.vault_approval_decided",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "approval_id": {"type": "string", "minLength": 1},
                "agent_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "provider": {"type": "string", "minLength": 1},
                "outcome": {"type": "string", "minLength": 1},
                "decided_by": {"type": "string", "minLength": 1}
            },
            "required": [
                "approval_id", "agent_id", "organization_id", "provider", "outcome",
                "decided_by"
            ]
        }"#,
    ),
    (
        // An operator gave an agent a downstream third-party credential (issue #132). It
        // carries the agent, the organization and the PROVIDER, and no part of the
        // credential: an event naming the secret would put it in every integrator's stream,
        // which is the opposite of what sealing it at rest is for.
        "agent.vault_connection_stored",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "agent_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "provider": {"type": "string", "minLength": 1}
            },
            "required": ["agent_id", "organization_id", "provider"]
        }"#,
    ),
    (
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
        // A schema VERSION was registered, not yet in force. Publishing the version alone --
        // and never the schema body -- keeps the event small and keeps a consumer honest: the
        // registry is the source of truth for the shape, and refetching it is one call.
        // A DCR policy decides who may self-register a client and on what terms, so a
        // receiver mirroring registration policy acts on it. The NAME travels with the id
        // because a policy is referred to by name in an operator's own configuration.
        // A quarantined signup was RESOLVED by an operator, one type carrying the decision.
        // Approve and reject are the same review reaching opposite conclusions over one
        // subject, so a consumer mirroring "may this person sign in" reads one field rather
        // than correlating two subscriptions -- the same shape as
        // `organization.state_changed`.
        //
        // EXTEND is deliberately NOT folded in: it resolves nothing. It moves the deadline and
        // leaves the subject quarantined, so a consumer that treated it as a decision would
        // admit or refuse someone still under review.
        // The SMS-OTP kill switch and its downgrade rule. Both are on the payload because the
        // pair is the policy: "enabled" alone does not tell a receiver whether a user may fall
        // back from a stronger factor, which is the part with security consequences.
        // A SIEM stream was configured. The SINK TYPE travels with the id because "audit is
        // now shipping to S3" and "audit is now shipping to an HTTP endpoint" are different
        // facts to anyone reconciling where a tenant's audit trail goes.
        //
        // NEVER THE SINK CREDENTIAL. A stream carries the secret its deliveries authenticate
        // with, sealed at rest and stripped from the read surface; a webhook is a wider
        // audience than that surface.
        // A bulk identity import was ACCEPTED. Long-running, so this announces the run
        // beginning rather than its outcome -- which is not knowable when the request returns.
        //
        // No counts and no records: an import's progress belongs to the run resource an
        // operator polls, and putting a snapshot of it on the wire would publish a number
        // that is stale before it is delivered.
        // A client-level PAR requirement. Requiring pushed authorization requests hardens
        // that client's authorize leg, so a consumer mirroring client hardening posture acts
        // on it -- and one type with the boolean rather than a required/not-required pair,
        // matching the other two-direction flags in this registry.
        // A routing rule decides WHICH UPSTREAM a login is sent to, so a consumer mirroring
        // federation topology acts on it. The rule and its organization connection are both
        // carried: the rule alone does not say where it routes.
        // A per-scope STEP-UP requirement: what a caller must satisfy before a token bearing
        // this scope is issued. Raising it hardens the scope and lowering it relaxes one, so
        // a consumer mirroring authentication policy acts on both.
        //
        // The SCOPE TOKEN is the address, and the requirement travels with it: `min_acr` and
        // `max_auth_age_secs` are both optional because a policy may constrain either, and
        // each is OMITTED when unset rather than sent as a sentinel.
        // An operator DECIDED a recovery request: someone locked out of their account either
        // regains access or does not. One type carrying the decision, because approve and
        // reject are the same review reaching opposite conclusions -- and a consumer must act
        // on both, since an approval is an account takeover if the request was fraudulent.
        //
        // NO `completed` FIELD, and the omission is forced rather than chosen. Whether the
        // approval also FINISHED the flow is the store's return value, discovered inside the
        // write; the producer builds its envelope BEFORE the call and cannot know it. A field
        // nothing can populate is worse than no field: a consumer would read its absence as
        // "not completed" rather than "not stated".
        // A PROJECT GRANT lets a client act for an organization, so a consumer mirroring
        // delegated authority acts on it. Both ends and the organization: the grant alone does
        // not say WHO may act for WHOM.
        "project_grant.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "project_grant_id": {"type": "string", "minLength": 1},
                "client_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["project_grant_id", "client_id", "organization_id"]
        }"#,
    ),
    (
        // WITHDRAWN, and its own type: this is the REVOCATION half, the one a receiver
        // deprovisions on. A consumer that missed it would keep honouring a client's authority
        // over an organization after an operator took it away.
        "project_grant.withdrawn",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "project_grant_id": {"type": "string", "minLength": 1}
            },
            "required": ["project_grant_id"]
        }"#,
    ),
    (
        // A BAN is a security mutation an operator performs believing it took effect, so a
        // consumer mirroring blocks acts on both halves. The subject VALUE stays off the wire
        // -- it is an IP, a canonical login identifier, or an account, the same class the
        // `user.identifier_*` types already withhold, and an event is a wider audience than
        // the management surface that returns it. The KIND and the auth path say which block
        // list changed; the id and the authorized list surface say the rest.
        //
        // The operator's free-text `reason` is withheld for the same reason: it is prose
        // somebody wrote ABOUT a person, and a consumer that needs it can read it there.
        "ban.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "ban_id": {"type": "string", "minLength": 1},
                "subject_kind": {"type": "string", "minLength": 1},
                "auth_path": {"type": "string", "minLength": 1},
                "expires_at_unix_ms": {"type": "integer"}
            },
            "required": ["ban_id", "subject_kind", "auth_path"]
        }"#,
    ),
    (
        // The RELAXING half, and its own type: a consumer that read a lift as a no-op would
        // keep blocking a subject an operator released.
        //
        // NO `ban_id`, and that asymmetry with `ban.created` is deliberate rather than an
        // omission. A create MINTS the id, so its producer knows it; a lift is ADDRESSED by
        // (subject, path) and the producer never learns which row matched. Inventing the id
        // here would mean reading it back out of the write, which is precisely the shape that
        // puts a value on the wire the producer cannot honestly claim.
        "ban.lifted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "subject_kind": {"type": "string", "minLength": 1},
                "auth_path": {"type": "string", "minLength": 1}
            },
            "required": ["subject_kind", "auth_path"]
        }"#,
    ),
    (
        // A journey VERSION is authored config: appending one changes nothing a user reaches
        // until it is pinned, and that is exactly why the two are separate types. A consumer
        // that treated an append as a rollout would announce a change no end user can see.
        //
        // The ARTIFACT does not travel. It is the journey document itself -- arbitrarily large
        // and versioned by this very mechanism -- and a consumer that wants it reads it back
        // by (journey, version), which is what this payload names.
        "flow_version.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "flow_version_id": {"type": "string", "minLength": 1},
                "journey_id": {"type": "string", "minLength": 1},
                "version": {"type": "integer"}
            },
            "required": ["flow_version_id", "journey_id", "version"]
        }"#,
    ),
    (
        // The ROLLOUT half: this is the one that changes what an end user walks through, so
        // it is the one a consumer mirroring live journey config acts on. Versions are
        // append-only, so the pinned version is the whole of the state -- there is no
        // unpinning, and a move is another pin.
        "flow_version.pinned",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "journey_id": {"type": "string", "minLength": 1},
                "version": {"type": "integer"}
            },
            "required": ["journey_id", "version"]
        }"#,
    ),
    (
        // Withdrawing consent revokes the client's standing authority to act for this user,
        // and it cascades: the refresh families go with it. A consumer mirroring delegated
        // access that missed this would keep an application authorized after the user said no.
        //
        // NO `families_revoked` count. It is knowable only AFTER the write, so a producer that
        // put it on the wire would be announcing something it read back out of its own
        // mutation -- and a grant that owned no live family is a real revocation either way.
        "consent.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "subject": {"type": "string", "minLength": 1},
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["subject", "client_id"]
        }"#,
    ),
    (
        // An operator was authorized to BECOME a user. This is the widest authority the
        // management surface hands out -- it reaches everything that user can reach -- so a
        // consumer running detection or oversight acts on it above almost anything else here.
        //
        // The expiry travels because the authorization is time-boxed and a receiver that
        // cannot see the box would have to treat every authorization as permanent. The
        // reason CODE travels because it is a registered classification. The reason TEXT does
        // not: it is prose an operator wrote about a person's account, the same class as a
        // ban's reason, and a consumer that needs it can read it in the audit trail where it
        // belongs.
        "impersonation.authorized",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "authorization_id": {"type": "string", "minLength": 1},
                "user_id": {"type": "string", "minLength": 1},
                "reason_code": {"type": "string", "minLength": 1},
                "expires_at_unix_ms": {"type": "integer"}
            },
            "required": ["authorization_id", "user_id", "reason_code", "expires_at_unix_ms"]
        }"#,
    ),
    (
        // A NEW environment is a new scope: a new issuer, a disjoint JWKS, and a place
        // tokens can be minted from. A consumer that provisions or monitors per environment
        // cannot discover one by watching the environments it already knows, so this is the
        // one announcement it has no other way to reach.
        //
        // Enqueued into the NEW environment's own outbox, which is where it belongs and also
        // the only place forced row-level security will accept it: the row must be written
        // under the environment it names.
        //
        // The KIND travels because it decides the guardrail class -- a production environment
        // and a development one are governed differently, and a consumer that treated them
        // alike would apply a development posture to production.
        "environment.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "environment_id": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1}
            },
            "required": ["environment_id", "kind"]
        }"#,
    ),
    (
        // A MANAGEMENT credential was minted: something that can now administer this
        // environment. A consumer running credential oversight acts on it, and this is the
        // moment to act -- the secret is shown once and never again.
        //
        // The secret does not travel, and neither does its HASH. The hash is a verifier: an
        // event carrying it hands every receiver the ability to check guesses offline, which
        // is the whole property hashing exists to deny. The database itself stores only the
        // hash, and the event stores less.
        "management_key.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "management_key_id": {"type": "string", "minLength": 1},
                "display_name": {"type": "string"}
            },
            "required": ["management_key_id", "display_name"]
        }"#,
    ),
    (
        // Permission claims decide whether tokens for this API carry the caller's permissions
        // INSIDE them. Turning it on changes what every downstream resource server sees in a
        // token it already knows how to parse; turning it off silently removes a claim
        // something may be authorizing on. Either way a consumer mirroring API config has to
        // learn it, and the direction is the whole content -- which is why the flag travels
        // rather than a bare "something changed".
        "resource_server.permission_claims_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "resource_server_id": {"type": "string", "minLength": 1},
                "enabled": {"type": "boolean"}
            },
            "required": ["resource_server_id", "enabled"]
        }"#,
    ),
    (
        // A CONFIG PROMOTION rewrites an environment's configuration wholesale from a
        // snapshot. It is the widest configuration change this surface makes, so a consumer
        // that caches anything about the environment has to invalidate on it.
        //
        // The revision, not the diff. The diff is the promotion document itself -- every
        // changed resource in the environment -- and putting it on the wire would publish a
        // whole configuration to every subscriber. The revision is what identifies WHICH
        // configuration now holds, and it is exactly what a consumer needs to ask whether the
        // copy it has is current.
        //
        // Only an APPLIED promotion announces. A no-op changed nothing.
        "config_promotion.applied",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "revision": {"type": "string", "minLength": 1}
            },
            "required": ["revision"]
        }"#,
    ),
    (
        // A management credential just gained SUDO: for the length of the window it may make
        // the mutations the freshness gate otherwise refuses. That is a privilege escalation
        // by design, and it is what an oversight consumer watches for.
        //
        // The EXPIRY travels because the elevation is a window, not a state: a receiver that
        // could not see the window would have to treat every elevation as permanent. The
        // achieved `acr` travels because it says what the re-authentication actually proved.
        "sudo.elevated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "actor_id": {"type": "string", "minLength": 1},
                "acr": {"type": "string", "minLength": 1},
                "expires_at_unix_ms": {"type": "integer"}
            },
            "required": ["actor_id", "acr", "expires_at_unix_ms"]
        }"#,
    ),
    (
        // A RESEND, the one management write on the messaging surface that causes mail.
        // `producer-coverage.py` found it announcing NOTHING, and a write that emits nothing is
        // invisible to every integrator watching the feed. For a resend that is the difference
        // between "an operator re-sent it" and "our provider double-delivered".
        //
        // NO ADDRESS and no body, for the reason `message.rate_limited` gives below: the feed is
        // the artifact a tenant hands to third-party sync targets, and a resend event is by
        // construction about somebody being mailed right now. `message_id` names the ledger row,
        // which is where a holder of the tenant's key looks up the rest.
        //
        // `attempt` is the durable answer to "why did this person get four copies", so it rides
        // the event rather than needing a follow-up read.
        //
        // EMITTED ONLY WHEN A RESEND ACTUALLY RE-QUEUED. `Resent` has FOUR variants and the
        // other THREE all wrote no mail: a SUPPRESSED recipient is a hard bounce or a complaint
        // the store refuses on the recipient's behalf, a message in a state a resend cannot act
        // on is a no-op, and a PAYLOAD the diagnostics retention sweep already reaped cannot be
        // re-queued at all. An event for any of them would tell a subscriber that mail went out
        // when none did, which is worse than the silence this replaces.
        //
        // The count is written out because an earlier version of this comment said "the other
        // two" and enumerated two, leaving the retention-expiry path -- the one whose behaviour
        // is least obvious -- unmentioned in the case analysis that justifies the guard.
        "message.resent",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "message_id": {"type": "string", "minLength": 1},
                "attempt": {"type": "integer", "minimum": 1}
            },
            "required": ["message_id", "attempt"]
        }"#,
    ),
    (
        // A send REFUSED by the per-recipient rate limit (issue #111 criterion 5), which asks
        // that exceeding the limit both block the send and emit this.
        //
        // The payload carries NO ADDRESS. A rate-limit event is, by construction, about a
        // recipient somebody is sending a lot of mail to, and the feed is the one artifact a
        // tenant hands to third-party sync targets: putting the address here would make the
        // event stream a directory of exactly the mailboxes under pressure, which is a list
        // worth stealing. The blind index identifies the recipient well enough to group and
        // to correlate with the ledger, and identifies them to nobody who does not already
        // hold the tenant's key.
        //
        // `retry_after_unix_seconds` is the instant the oldest counted send leaves the
        // window, so a consumer can tell a user when to come back rather than leaving them to
        // guess. `kind` is the message kind, because "we are rate limiting your login codes"
        // and "we are rate limiting your marketing" are different operational facts.
        "message.rate_limited",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "recipient_bidx": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1},
                "retry_after_unix_seconds": {"type": "integer"}
            },
            "required": ["recipient_bidx", "kind", "retry_after_unix_seconds"]
        }"#,
    ),
    (
        // THE THREE TYPES METERING COUNTS (issue #107). They are registered here, beside
        // every other type, because `UsageTally` names them as string constants and an
        // unregistered type is refused by `validate_event` at the fan-out -- so a metering
        // event that was not in this list could never be delivered, and the fold would read
        // a feed that never contains what it counts.
        //
        // The SUBJECT is what makes an active user active, and it is the only field the fold
        // reads. It is the pseudonymous subject identifier, not an email or a phone number:
        // metering needs to distinguish people, not identify them, and a billing pipeline is
        // exactly the kind of downstream system that should never have been handed a
        // directory of its customer's users.
        "user.signed_in",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "subject": {"type": "string", "minLength": 1}
            },
            "required": ["subject"]
        }"#,
    ),
    (
        // Token issuance is COUNTED, never described. No token and no jti: the fold
        // increments a number, and the token itself would be material about a live
        // credential handed to every subscriber of the feed in order to count to one.
        //
        // The GRANT and the KIND, because they are what the producer holds. An earlier draft
        // of this schema required `client_id`, which reads better and is wrong: the issuance
        // path carries `IssuedTokenRecord { id, kind }` and the grant, and resolving the
        // client would mean an extra read on the token path -- the producer announcing
        // something it had to go and look up. A consumer that wants the client resolves the
        // grant through the management surface, which is the same trade every other payload
        // here makes.
        //
        // The KIND rides along because an access token and an ID token are not
        // interchangeable units: an operator reading issuance volume needs to know which.
        "token.issued",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "grant_id": {"type": "string", "minLength": 1},
                "token_kind": {"type": "string", "minLength": 1}
            },
            "required": ["grant_id", "token_kind"]
        }"#,
    ),
    (
        // A CONNECTION is an upstream identity provider binding. Metering counts them per
        // tenant, and the connection id is what lets an operator reconcile a count they
        // disagree with against the connections they can list.
        "connection.opened",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "connection_id": {"type": "string", "minLength": 1}
            },
            "required": ["connection_id"]
        }"#,
    ),
    (
        // A template override decides what an end user READS in a message they receive, so a
        // consumer mirroring branding or compliance copy acts on it. SET rather than
        // created-or-updated because the write is an upsert keyed on
        // (level, organization, kind, locale): distinguishing the two would need the store to
        // read the row back first, and a receiver re-reads the template either way.
        //
        // The BODY does not travel. It is authored content, arbitrarily large, and a webhook
        // is a wider audience than the management surface that returns it -- the same refusal
        // the brand design document gets. What travels is enough to know WHICH template
        // changed: the level, the kind, and the locale.
        "message_template.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "message_template_id": {"type": "string", "minLength": 1},
                "level": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1},
                "locale": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["message_template_id", "level", "kind", "locale"]
        }"#,
    ),
    (
        // Removing an override RESTORES the next level up, which is a change to what
        // recipients read just as much as setting one was. A consumer told nothing would keep
        // serving copy that no longer applies.
        "message_template.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "message_template_id": {"type": "string", "minLength": 1},
                "level": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1},
                "locale": {"type": "string", "minLength": 1}
            },
            "required": ["message_template_id", "level", "kind", "locale"]
        }"#,
    ),
    (
        // A flow target is an EXTENSION POINT: registering one means an external endpoint now
        // sees, and for a sync target can reject, data flowing through this environment. A
        // consumer running configuration oversight acts on that above most things here.
        //
        // The TIMING and INVOCATION travel because they are what makes a target consequential:
        // a sync pre-persist target can refuse a signup, and an async post-persist one cannot.
        // A consumer told only "a target changed" cannot tell those apart.
        //
        // The ENDPOINT does not travel. It is operator-configured infrastructure detail, often
        // an internal address, and a webhook is a wider audience than the management surface
        // that returns it.
        "flow_target.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "flow_target_id": {"type": "string", "minLength": 1},
                "name": {"type": "string", "minLength": 1},
                "target_class": {"type": "string", "minLength": 1},
                "invocation": {"type": "string", "minLength": 1},
                "timing": {"type": "string", "minLength": 1}
            },
            "required": [
                "flow_target_id",
                "name",
                "target_class",
                "invocation",
                "timing"
            ]
        }"#,
    ),
    (
        // Deregistering STOPS an extension point. A consumer that missed it would keep
        // believing an integration is inspecting flows that nothing inspects any more, which
        // for a fraud or compliance target is a control believed to be in place and absent.
        "flow_target.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "flow_target_id": {"type": "string", "minLength": 1},
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["flow_target_id", "name"]
        }"#,
    ),
    (
        // An operator asked for a target's dead-lettered async deliveries to be REPLAYED
        // (issue #112 criterion 2). A consumer wants this because a replay re-POSTs signup
        // announcements a receiver already had the chance to see: anything reconciling
        // against the target's own records needs to know a redelivery burst was deliberate
        // rather than a fault.
        //
        // NO NAME, unlike the two above. The replay route addresses a target by id and never
        // reads its name, and a schema that required one would force a second read whose only
        // purpose is to satisfy the schema -- or, worse, an empty string that the fan-out
        // rejects permanently and silently in a release build.
        //
        // `since_unix_ms` travels because "replay everything" and "replay since noon" are
        // materially different acts against a third party, and a consumer reconciling a
        // redelivery burst needs to know which one it was. Null means everything.
        "flow_target.replay_requested",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "flow_target_id": {"type": "string", "minLength": 1},
                "since_unix_ms": {"type": ["integer", "null"]}
            },
            "required": ["flow_target_id"]
        }"#,
    ),
    (
        // The METERING SNAPSHOT, so usage exports by webhook and not only by polling the API
        // (issue #107 criterion 4: "exports via API and webhook").
        //
        // A billing pipeline wants the aggregate PUSHED. Deriving it from the raw feed means
        // every consumer re-implements the fold -- including its truncation rule -- and two
        // implementations of a billing number is how a customer gets two different invoices.
        //
        // NO PER-USER DATA. `monthly_active_users` is a COUNT, never a list: metering needs
        // to distinguish people, not identify them, and a billing pipeline is exactly the
        // downstream system that should never be handed a directory of its customer's users.
        //
        // `truncated` travels because the numbers are meaningless without it. When the fold
        // stops at its limit these are a LOWER BOUND, and a silently truncated usage figure
        // is the one number a customer would never think to question.
        "usage.reported",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "monthly_active_users": {"type": "integer", "minimum": 0},
                "tokens_issued": {"type": "integer", "minimum": 0},
                "connections": {"type": "integer", "minimum": 0},
                "truncated": {"type": "boolean"}
            },
            "required": ["monthly_active_users", "tokens_issued", "connections", "truncated"]
        }"#,
    ),
    (
        "recovery_approval.decided",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "recovery_flow_id": {"type": "string", "minLength": 1},
                "decision": {"type": "string", "minLength": 1}
            },
            "required": ["recovery_flow_id", "decision"]
        }"#,
    ),
    (
        "step_up_policy.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "scope_token": {"type": "string", "minLength": 1},
                "min_acr": {"type": "string", "minLength": 1},
                "max_auth_age_secs": {"type": "integer"}
            },
            "required": ["scope_token"]
        }"#,
    ),
    (
        // The requirement is GONE, which means the scope no longer demands a step-up. That is
        // a relaxation, and its own type: a consumer must not read "policy removed" as
        // "policy unchanged".
        "step_up_policy.removed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "scope_token": {"type": "string", "minLength": 1}
            },
            "required": ["scope_token"]
        }"#,
    ),
    (
        "routing_rule.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "routing_rule_id": {"type": "string", "minLength": 1},
                "org_connection_id": {"type": "string", "minLength": 1}
            },
            "required": ["routing_rule_id", "org_connection_id"]
        }"#,
    ),
    (
        // Domain verification is the GATE on a routing rule taking effect: an unverified
        // domain must not silently route anyone's login to an upstream. One type with the
        // boolean, because verifying and un-verifying are the same check reaching opposite
        // conclusions -- and a consumer needs to act on BOTH, since losing verification is
        // what stops a rule routing.
        "routing_rule.domain_verification_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "routing_rule_id": {"type": "string", "minLength": 1},
                "verified": {"type": "boolean"}
            },
            "required": ["routing_rule_id", "verified"]
        }"#,
    ),
    (
        // The pre-authorization GRANT, the counterpart of `admin_consent.revoked`: it lets a
        // client SKIP the consent screen, so a consumer mirroring standing authority needs
        // the widening as well as the narrowing.
        //
        // NO grant id, and the asymmetry with the revoke is deliberate. A set is an upsert
        // that REUSES the existing row's id, resolved inside the write, so the producer holds
        // only the id it minted -- which is the row id on a first write and a stale invention
        // on an overwrite. The client is what an operator addressed and what identifies the
        // pre-authorization; the grant id is an internal handle.
        "admin_consent.granted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "granted_scope": {"type": "string", "minLength": 1}
            },
            "required": ["client_id"]
        }"#,
    ),
    (
        // Whether the client is RESTRICTED, not which scopes it may request. The allowlist is
        // config a consumer re-reads through the authorized surface; what it cannot re-derive
        // is that the restriction was turned on or off at all, because a client with no
        // allowlist and a client allowlisted for everything read the same from a single
        // scope's point of view.
        //
        // An EMPTY allowlist is restricted, and maximally so. It is a real stored value,
        // distinct from the NULL clear, and a consumer that conflated the two would read the
        // most restrictive client in the environment as the least.
        "client.allowed_scopes_set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "restricted": {"type": "boolean"}
            },
            "required": ["client_id", "restricted"]
        }"#,
    ),
    (
        // The id-token signing algorithm is what a RELYING PARTY must verify with, so a
        // consumer that mirrors client config has to learn the change or it keeps verifying
        // with the old algorithm and rejects every token the client is now issued.
        //
        // The JOSE name travels because it IS the fact: a short registered identifier, not a
        // document, and a consumer told only "something changed" would have to refetch to
        // learn the one thing this event exists to say.
        "client.signing_algorithm_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "id_token_signed_response_alg": {"type": "string", "minLength": 1}
            },
            "required": ["client_id", "id_token_signed_response_alg"]
        }"#,
    ),
    (
        // A human's decision on a CIBA backchannel request (issue #131 criterion 1).
        //
        // CIBA's shape is that the thing asking is not the thing approving, so "who said yes
        // to this, and when" is not recoverable from anything else on the stream: the client
        // only ever learns that its poll started succeeding. Carried on the DECISION rather
        // than on the redemption because a denial issues nothing and would otherwise be
        // invisible, and a denial is the half a fraud team most wants to see.
        "backchannel_request.decided",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "request_id": {"type": "string", "minLength": 1},
                "approved": {"type": "boolean"}
            },
            "required": ["request_id", "approved"]
        }"#,
    ),
    (
        // The per-client DPoP exemption (issue #124). This one RELAXES a control rather than
        // tightening one: `allowed: true` means this client's tokens stop being
        // sender-constrained and become replayable by whoever steals them. An integrator
        // watching the stream for security-posture changes needs to see it for exactly that
        // reason, which is also why the payload states the direction rather than only naming
        // the client.
        "client.bearer_tokens_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "allowed": {"type": "boolean"}
            },
            "required": ["client_id", "allowed"]
        }"#,
    ),
    (
        "client.par_requirement_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "required": {"type": "boolean"}
            },
            "required": ["client_id", "required"]
        }"#,
    ),
    (
        // The environment's AUTO-LINK posture: what happens when a federated identity arrives
        // matching an existing account. It decides whether an upstream can silently take over
        // a local account, so it is squarely a security posture rather than a preference.
        //
        // `posture` is ABSENT when the override is CLEARED and the deployment default takes
        // over -- mirroring the nullable column, and matching the rule the subscription and
        // reparent payloads set: no invented sentinel for "none".
        "environment.auto_link_posture_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "posture": {"type": "string", "minLength": 1}
            },
            "required": []
        }"#,
    ),
    (
        "identity_import.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "migration_run_id": {"type": "string", "minLength": 1}
            },
            "required": ["migration_run_id"]
        }"#,
    ),
    (
        // The run MOVED, carrying the state it moved to. One type with a state rather than one
        // per transition: a consumer tracking "is this import still going" reads one field,
        // and the state machine can gain a state without minting a new event type -- which
        // would otherwise be a breaking registry change for a purely internal addition.
        "identity_import.state_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "migration_run_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1}
            },
            "required": ["migration_run_id", "state"]
        }"#,
    ),
    (
        "log_stream.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "log_stream_id": {"type": "string", "minLength": 1},
                "sink_type": {"type": "string", "minLength": 1}
            },
            "required": ["log_stream_id", "sink_type"]
        }"#,
    ),
    (
        // An operator ASKED for a replay. Separate from any later "replayed" notice because
        // the request and the delivery are separated by a worker: the command is accepted
        // synchronously and executed later, so this is the only event that can be emitted in
        // the request's own transaction.
        "log_stream.replay_requested",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "log_stream_id": {"type": "string", "minLength": 1}
            },
            "required": ["log_stream_id"]
        }"#,
    ),
    (
        // The stream is gone AND so is every dead letter it recorded, which is why this
        // matters more than a configuration tidy-up: an operator watching for undelivered
        // audit will never see those again, and the event is the only notice they get.
        "log_stream.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "log_stream_id": {"type": "string", "minLength": 1}
            },
            "required": ["log_stream_id"]
        }"#,
    ),
    (
        "sms_otp.config_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {"type": "boolean"},
                "allow_factor_downgrade": {"type": "boolean"}
            },
            "required": ["enabled", "allow_factor_downgrade"]
        }"#,
    ),
    (
        // ONE type with the country and the direction. An allowlist is a set, and adding to it
        // or removing from it are the same edit in two directions -- a consumer mirroring
        // "where may we send" reads one field rather than correlating two subscriptions.
        //
        // The COUNTRY is the payload's reason for existing: the allowlist is what stands
        // between this surface and toll fraud, and a receiver auditing it needs to know which
        // destination changed, not merely that something did.
        "sms_otp.allowlist_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "country_code": {"type": "string", "minLength": 1},
                "allowed": {"type": "boolean"}
            },
            "required": ["country_code", "allowed"]
        }"#,
    ),
    (
        "signup_quarantine.resolved",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "decision": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "decision"]
        }"#,
    ),
    (
        // The review WINDOW moved; the subject is still quarantined. Carrying the new deadline
        // is the point: an operator dashboard counting "reviews due today" is wrong until it
        // knows the new instant.
        "signup_quarantine.extended",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "quarantined_until_unix_ms": {"type": "integer"}
            },
            "required": ["user_id", "quarantined_until_unix_ms"]
        }"#,
    ),
    (
        "dcr_policy.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "dcr_policy_id": {"type": "string", "minLength": 1},
                "name": {"type": "string", "minLength": 1}
            },
            "required": ["dcr_policy_id", "name"]
        }"#,
    ),
    (
        // An initial access token was MINTED: a bearer credential that lets its holder
        // register a client. THE TOKEN ITSELF IS NEVER ON THE WIRE -- it is the credential,
        // and it is live at exactly this moment. The id is what an operator revokes by.
        "dcr_initial_access_token.minted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "initial_access_token_id": {"type": "string", "minLength": 1}
            },
            "required": ["initial_access_token_id"]
        }"#,
    ),
    (
        // A dynamically registered client was VERIFIED by an operator: it moves from
        // self-asserted to vouched-for, which is the transition a downstream policy engine
        // would gate on. Distinct from `client.deleted` and from any registration event
        // because nothing about the client CHANGED except an operator's judgement of it.
        "client.verified",
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
        "trait_schema.version_created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "version": {"type": "integer"}
            },
            "required": ["version"]
        }"#,
    ),
    (
        // ITS OWN TYPE, and the consequential one of the pair: creating a version changes
        // nothing a user can observe, ACTIVATING it changes how every trait in the
        // environment is validated from that moment. A consumer that treated the two alike
        // would apply a schema before it was in force.
        "trait_schema.version_activated",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "version": {"type": "integer"}
            },
            "required": ["version"]
        }"#,
    ),
    (
        // A long-running JOB was accepted, not completed. The KIND is carried because a dry
        // run and a real migration are very different things to a receiver watching for trait
        // changes: one will rewrite rows, the other never will.
        "trait_migration_job.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "job_id": {"type": "string", "minLength": 1},
                "kind": {"type": "string", "minLength": 1}
            },
            "required": ["job_id", "kind"]
        }"#,
    ),
    (
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
        // A PERMISSION on a ROLE: the grant that actually decides what a role can do. Every
        // holder of the role gains or loses it at once, so a consumer recomputing effective
        // permissions acts on this even though no membership changed.
        //
        // Both ends and the organization, as with the role assignments: neither the role nor
        // the permission alone tells a receiver what changed.
        "org_role.permission_granted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "permission_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "org_role_id", "permission_id"]
        }"#,
    ),
    (
        "org_role.permission_revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "org_role_id": {"type": "string", "minLength": 1},
                "permission_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "org_role_id", "permission_id"]
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
        // A claim mapping decides the SHAPE OF EVERY TOKEN a client is issued: which claims it
        // carries, under what names, and in which of the two tokens. Changing one changes what
        // every resource server downstream sees, so it belongs on the stream a SIEM watches.
        //
        // THE CLIENT ONLY, and no rules. The client is the stable address (this table has no id
        // of its own and the write is an upsert keyed on it), and the rules are configuration a
        // consumer refetches rather than something a notification should carry: an event that
        // embedded them would put the whole document on every stream that subscribes.
        "claims_mapping.set",
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
        // Removing a mapping restores the UNMAPPED token, and that is a change in BOTH
        // directions: claims the mapping filtered out come back to the ID token, and a claim it
        // had placed in the access token stops reaching one. Both are why it belongs on an
        // audit stream -- a consumer cannot tell which without refetching, and either can break
        // something downstream.
        "claims_mapping.deleted",
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
        // A hook is CODE that runs inside the token mint, so a deploy changes what every token
        // this client is issued can contain -- by computation rather than by rearrangement,
        // which is strictly more than a claim mapping does. It belongs on the stream a SIEM
        // watches for the same reason, with more force.
        //
        // NO `failure_policy` ON THIS EVENT, and the reason is worth the paragraph because two
        // successive attempts to add it were both wrong.
        //
        // Review asked for it so a redeploy changing only the policy is distinguishable from
        // the one before. Added as REQUIRED, it is a breaking change under an unchanged version
        // and `scripts/event-registry-compat.py` goes red: during a rolling upgrade an OLD pod
        // emits the three-field payload and a NEW pod's fan-out, which validates on CONSUME,
        // refuses it permanently as `event_failed_catalog_validation`.
        //
        // Added as OPTIONAL, the gate passes and the SAME failure happens in the other
        // direction. This schema is `additionalProperties: false`, so a NEW pod emitting the
        // field and an OLD pod's outbox worker claiming that row -- nothing binds a message to
        // the pod that produced it -- yields "additional field is not permitted", another
        // permanent dead-letter, and explode fails before any per-endpoint delivery row exists
        // so there is nothing for the replay endpoint to replay.
        //
        // Adding ANY property to a closed schema is therefore breaking for a consumer running
        // the older registry, whatever the `required` list says. Doing it safely needs the
        // consumer to tolerate unknown fields first, which is a change to every registered
        // type rather than to this one. So the policy is not on the event: a consumer that
        // needs it reads it from the management API, and losing every deploy notification
        // during an upgrade window is a worse trade than a redeploy that looks identical.
        //
        // THE CLIENT AND THE SHAPE, never the component. An event is a notification, not a
        // binary store: the bytes are already durable in the row this points at, and putting
        // megabytes of WASM on every subscriber's stream would be a denial of service dressed
        // as an announcement. The byte count and the payload version are what let a consumer
        // tell one deploy from another without refetching.
        "token_hook.deployed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "component_bytes": {"type": "integer", "minimum": 1},
                "payload_version": {"type": "integer", "minimum": 0}
            },
            "required": ["client_id", "component_bytes", "payload_version"]
        }"#,
    ),
    (
        // Removing a hook restores the UNSHAPED token: a claim the hook computed stops being
        // minted, so a resource server authorizing on it starts refusing. A consumer cannot
        // tell that from silence, which is exactly why the removal announces itself.
        "token_hook.deleted",
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
        // A GRANT widens what DEPLOYED CODE may read, and it takes effect on the NEXT ISSUANCE
        // with no redeploy, because the dispatch resolves grants per invocation. So a consumer
        // watching what a client's hooks can reach cannot infer this from a deploy event: there
        // may not be one.
        //
        // THE SECRET NAME, NEVER A VALUE, for the reason the grant table itself exists: it
        // stores a reference so the value stays sealed behind a different repository and the
        // platform key.
        "token_hook.secret_granted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "hook_name": {"type": "string", "minLength": 1},
                "secret_name": {"type": "string", "minLength": 1}
            },
            "required": ["client_id", "hook_name", "secret_name"]
        }"#,
    ),
    (
        // The withdrawal of the capability above, and the one an operator reaches for when a
        // hook is misusing a secret. Both edges are announced because a consumer tracking what
        // code may read needs both, and because this one is the remediation.
        "token_hook.secret_revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "hook_name": {"type": "string", "minLength": 1},
                "secret_name": {"type": "string", "minLength": 1}
            },
            "required": ["client_id", "hook_name", "secret_name"]
        }"#,
    ),
    (
        // A client's hooks run as an ORDERED CHAIN, and each one sees what the previous left. So
        // reordering changes what every token that client is issued carries, without any hook's
        // code changing -- which is precisely the change a consumer cannot see from a deploy
        // event, because there is no deploy.
        //
        // THE RESULTING ORDER, by name, because that IS the change. Unlike every other payload
        // here the address alone would say nothing: "the chain was reordered" without the order
        // is a notification a consumer has to refetch to act on, and the order is a short list
        // of names rather than a document.
        "token_hook.reordered",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "client_id": {"type": "string", "minLength": 1},
                "order": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1}
                }
            },
            "required": ["client_id", "order"]
        }"#,
    ),
    (
        // A CUSTOM FACTOR COMPONENT decides whether a login succeeds (issue #114 criterion 6).
        // Deploying one is deploying CODE onto the login path, so a consumer watching an
        // environment's security posture needs to see it land -- and unlike a token hook, which
        // shapes a token the login already earned, this decides whether it is earned at all.
        //
        // THE NAME AND THE SHAPE, never the component, for the reason `token_hook.deployed`
        // gives: an event is a notification and not a binary store, and putting sixteen
        // megabytes of WASM on every subscriber's stream would be a denial of service dressed as
        // an announcement.
        //
        // The NAME rather than an id, because a component has no id of its own: it is deployed
        // against the environment and referenced BY NAME from a journey step, so the name is the
        // stable address an operator and a consumer both use.
        "challenge_component.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "component_bytes": {"type": "integer", "minimum": 1},
                "payload_version": {"type": "integer", "minimum": 0}
            },
            "required": ["name", "component_bytes", "payload_version"]
        }"#,
    ),
    (
        // Removing a component a journey still names makes every login that reaches that step
        // REFUSE -- a factor fails closed. A consumer cannot tell that from silence, which is
        // why the removal announces itself separately from the deploy.
        "challenge_component.deleted",
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
        // A GRANT is a capability change: it widens what deployed code may read. Announced on
        // its own rather than folded into whatever deploy accompanied it, for the reason the
        // audit action gives -- an operator reading why a component could suddenly read a
        // signing key must FIND the grant, not infer it from a redeploy.
        //
        // THE SECRET NAME, NEVER A VALUE. The whole point of the grant table is that it stores a
        // reference and the value lives sealed behind a different repository and the platform
        // key. An event carrying the value would undo that in one line.
        "challenge_component.secret_granted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "secret_name": {"type": "string", "minLength": 1}
            },
            "required": ["name", "secret_name"]
        }"#,
    ),
    (
        // The withdrawal of the capability above. Its own type because a consumer tracking what
        // code may read needs both edges, and because the two are different operator decisions.
        "challenge_component.secret_revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "secret_name": {"type": "string", "minLength": 1}
            },
            "required": ["name", "secret_name"]
        }"#,
    ),
    (
        // A SESSION TOKENIZER TEMPLATE names the AUDIENCE that will accept short-lived JWTs for
        // this environment's subjects, and the TTL for which nothing can withdraw one (issue
        // #119). That is the highest-value configuration change this feature has, and a consumer
        // watching an environment's security posture should not have to poll for it.
        //
        // THE TTL RIDES ALONG, and it is not decoration: it is the exact width of the window in
        // which a revoked session's already-minted token still verifies. A consumer that tracks
        // revocation latency reads this number, and refetching the template to learn it would
        // make the event useless for that.
        //
        // NEVER THE RULES and never key material. The rules are configuration a consumer
        // refetches -- `claims_mapping.set` gives the reason -- and the key's only public
        // projection is the JWK at the template's own JWKS URL, which is a different surface
        // with a different reader.
        "session_token_template.set",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "audience": {"type": "string", "minLength": 1},
                "ttl_seconds": {"type": "integer", "minimum": 1}
            },
            "required": ["name", "audience", "ttl_seconds"]
        }"#,
    ),
    (
        // Deleting a template takes its KEYS with it, so its JWKS URL stops answering and every
        // consumer verifying against it starts failing. That is an outage with a cause, and this
        // is the event that names the cause.
        "session_token_template.deleted",
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
        // The OPT-IN JWT SESSION MODE going ON (issue #119 criterion 4). This moves EVERY session
        // check in the environment off the database and onto a token that keeps verifying until
        // it expires -- the single most consequential configuration flip this product has, and
        // the one an auditor most needs to see without polling.
        //
        // The TEMPLATE it was pointed at, because that names the audience and the TTL that now
        // govern every session in the environment.
        "session_jwt_mode.enabled",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "template": {"type": "string", "minLength": 1}
            },
            "required": ["template"]
        }"#,
    ),
    (
        // And going OFF. The SAFE direction -- every SDK returns to the database-backed check --
        // but still a change every request in the environment feels, and a load characteristic
        // somebody sized for. It names the template it WAS pointed at, so the row still says
        // what was turned off.
        "session_jwt_mode.disabled",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "template": {"type": "string", "minLength": 1}
            },
            "required": ["template"]
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
        // The id and the ORGANIZATION, because a SCIM connection provisions INTO exactly one
        // organization and a consumer routing on "who gained a provisioning credential"
        // cannot get that from the id. The PROVIDER too: a SIEM correlating a new connection
        // with traffic from Okta or Entra needs to know which one to expect.
        //
        // NO TOKEN and no digest, for the reason `api_key.created` gives: the digest verifies
        // exactly as well as the token does, so putting it on the wire that announces the
        // credential exists would BE the leak.
        "scim_connection.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "scim_connection_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1},
                "provider": {"type": "string", "minLength": 1}
            },
            "required": ["scim_connection_id", "organization_id", "provider"]
        }"#,
    ),
    (
        // Emitted at most ONCE per connection. Revocation is idempotent -- a retried revoke
        // changes nothing and audits nothing -- and the event inherits that, so a receiver
        // counting revocations never sees two because a client retried.
        //
        // The organization travels here too, unlike `api_key.revoked`: a receiver reacting to
        // "provisioning into this organization has stopped" would otherwise have to have kept
        // the created event to know which organization it was.
        "scim_connection.revoked",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "scim_connection_id": {"type": "string", "minLength": 1},
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["scim_connection_id", "organization_id"]
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
        // Workload identity federation (issue #126). A trust anchor decides WHOSE SIGNATURE
        // can mint a token in this environment, which makes the six that follow the
        // highest-value configuration events on the surface: a receiver reconciling "who can authenticate
        // here" against its own expectations reads them and nothing else.
        //
        // The issuer STRING is carried alongside the row id because it, not the id, is what
        // an assertion presents and what an operator recognises. `enabled` is carried so a
        // receiver READS the resulting state rather than inferring it from the event name,
        // which is the same reason the toggle event carries it. Today the registration route
        // always creates a live anchor, so this is always true; it is a field rather than an
        // implication so that a later staged registration cannot silently change what an
        // existing receiver believes.
        //
        // The key material is deliberately NOT carried. A pinned `jwks` is a public key set,
        // but it is unbounded in size and a receiver that wants it can read the anchor back;
        // putting it on every delivery would make the highest-frequency field the one nobody
        // reads.
        "external_issuer.registered",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "issuer_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1},
                "enabled": {"type": "boolean"}
            },
            "required": ["issuer_id", "issuer", "enabled"]
        }"#,
    ),
    (
        // The revocation direction, and the one a receiver most needs: a disabled anchor
        // stops authenticating workloads at that instant. `enabled` carries the RESULTING
        // state rather than naming a direction, matching `webhook_endpoint.active_changed`,
        // so a receiver that missed an earlier event still converges on the truth.
        //
        // The issuer string is carried as well as the row id, because it is this event's
        // ordering key and the thing a receiver reconciles trust by. Without it the toggle
        // would be the one event on this resource whose key could not be recovered from its
        // own payload, so a receiver that had not seen the registration could not tell which
        // issuer had just stopped being honoured.
        "external_issuer.enabled_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "issuer_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1},
                "enabled": {"type": "boolean"}
            },
            "required": ["issuer_id", "issuer", "enabled"]
        }"#,
    ),
    (
        // A mapping decides which principal a foreign subject BECOMES, so all three of the
        // issuer, the external subject and the mapped principal are carried: any two of them
        // without the third leaves a receiver unable to say who gained the ability to act as
        // whom. The optional claim gate is not carried, because a receiver reconciling trust
        // reads the rule back for its conditions; what the event has to deliver is that the
        // rule now exists and what it grants.
        "subject_mapping.created",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mapping_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1},
                "external_subject": {"type": "string", "minLength": 1},
                "principal": {"type": "string", "minLength": 1}
            },
            "required": ["mapping_id", "issuer", "external_subject", "principal"]
        }"#,
    ),
    (
        // The deletion is a DISTINCT type from the disable, because they mean different
        // things to a receiver reconciling trust: a disabled anchor still exists and can be
        // switched back, a deleted one is gone and its issuer string is free to be registered
        // again with a different key source. Collapsing them would make a repoint (delete then
        // re-register) indistinguishable from a revocation.
        "external_issuer.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "issuer_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1}
            },
            "required": ["issuer_id", "issuer"]
        }"#,
    ),
    (
        // The issuer and external subject are carried for the same reason the creation carries
        // them: they are the natural key a receiver tracks trust by, and after the row is gone
        // the id resolves to nothing, so an event carrying only the id could not be reconciled
        // against anything.
        "subject_mapping.deleted",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mapping_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1},
                "external_subject": {"type": "string", "minLength": 1}
            },
            "required": ["mapping_id", "issuer", "external_subject"]
        }"#,
    ),
    (
        // The mapping's revocation direction, resulting state for the same reason the
        // anchor's is.
        "subject_mapping.enabled_changed",
        1,
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mapping_id": {"type": "string", "minLength": 1},
                "issuer": {"type": "string", "minLength": 1},
                "external_subject": {"type": "string", "minLength": 1},
                "enabled": {"type": "boolean"}
            },
            "required": ["mapping_id", "issuer", "external_subject", "enabled"]
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
    let entry = registered(event_type)?;
    // Refuse to build an environment-scoped envelope for a type that names no environment.
    // `validate_event` would refuse it at the fan-out anyway, but that is delivery time: the
    // write would already have committed and the notice would be enqueued and undeliverable.
    // Failing here means the producer gets `None` and the write never happens.
    if !entry.environment_scoped {
        return None;
    }
    Some(serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": entry.payload_version,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "tenant_id": tenant_id,
        "environment_id": environment_id,
        "payload": payload,
    }))
}

/// [`envelope`] for a TENANT-SCOPED type: no `environment_id`, because the fact is not about
/// one environment.
///
/// A separate constructor rather than an `Option<&str>` parameter, so the choice is made by
/// which function a producer calls rather than by a value it might default. Each refuses the
/// other's types: this one returns `None` for an environment-scoped type and `envelope`
/// returns `None` for a tenant-scoped one, so a producer cannot reach the fan-out with the
/// wrong shape.
///
/// # Errors
///
/// `None` when the type is unregistered, or is registered as environment-scoped.
#[must_use]
pub fn envelope_tenant_scoped(
    id: &str,
    event_type: &str,
    tenant_id: &str,
    occurred_at_unix_ms: i64,
    payload: &serde_json::Value,
) -> Option<serde_json::Value> {
    let entry = registered(event_type)?;
    if entry.environment_scoped {
        return None;
    }
    Some(serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": entry.payload_version,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "tenant_id": tenant_id,
        "payload": payload,
    }))
}

/// The types that name NO single environment, listed explicitly.
///
/// Not derived from the domain, which is the obvious shortcut and is wrong: `tenant.created`
/// is in the `tenant` domain and legitimately carries an environment id, because creating a
/// tenant creates its first environment in the same transaction and the event names it. A
/// domain rule would have refused that event.
///
/// Listing means a new tenant-scoped type must be added here. Forgetting fails LOUDLY at the
/// first emit rather than silently: `validate_event` requires an environment id for anything
/// not on this list, so a producer that omits one is refused before delivery.
const TENANT_SCOPED: &[&str] = &[
    "tenant.deleted",
    "tenant.purged",
    "tenant.restored",
    "tenant.resumed",
    "tenant.suspended",
];

// RETIRED: `TARGET_REGISTERED_TYPES`, issue #108's count-based reminder that the catalog was
// incomplete. It was reached, which is exactly the moment its own failure message said to
// retire it rather than raise it.
//
// A COUNT was the right instrument while the catalog was empty and the question was "has
// anybody written producers yet". It is the wrong one now, and raising it would have been
// worse than useless: a higher number is not a stronger claim, because nothing ties any
// particular count to coverage. Twenty more types about one subsystem would clear any bar a
// count can set while leaving a whole surface silent.
//
// What replaced it measures the thing the count was standing in for. `scripts/producer-
// coverage.py` walks the management router, finds every write handler, and requires each one
// to reach a producer; it is a shrink-only ratchet wired into `scripts/gate.sh` and CI, and
// its baseline is now EMPTY (126/126). A new write handler that announces nothing fails that
// gate on the pull request that adds it -- which is the guarantee a number never gave.

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
    /// Whether this type names one environment.
    ///
    /// True for every type about something INSIDE an environment, which is all of them so
    /// far. False for a tenant-scoped type: deleting a tenant fences all of its environments
    /// at once, so naming one would assert something untrue about the other.
    pub environment_scoped: bool,
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
            environment_scoped: !TENANT_SCOPED.contains(wire),
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
    // `environment_id` per type, which is what keeps the twenty environment-scoped types
    // exactly as strict as they were before it left the envelope's blanket `required` list.
    //
    // BOTH directions are enforced. Requiring it where it belongs is the obvious half; the
    // other half matters more, because a tenant-scoped event carrying SOME environment id
    // would be worse than one carrying none -- a receiver would scope a tenant-wide fact to
    // whichever environment the store happened to pick, and act on it there alone.
    let has_environment = envelope
        .get("environment_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if entry.environment_scoped && !has_environment {
        return Err(CatalogError::Envelope(vec![
            "/environment_id: required for an environment-scoped event type".to_owned(),
        ]));
    }
    if !entry.environment_scoped && has_environment {
        return Err(CatalogError::Envelope(vec![
            "/environment_id: a tenant-scoped event names no single environment".to_owned(),
        ]));
    }
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
    fn the_registry_is_non_empty_and_no_two_types_share_a_wire_string() {
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
        // No count assertion here any more; see the retirement note on the constant it used
        // to read. Coverage is measured against the ROUTER by `scripts/producer-coverage.py`,
        // which a count could never do. What stays here is what a registry can check about
        // itself: it is non-empty, and no two types share a wire string.
    }

    /// English past forms that do NOT end in `-ed`, listed exactly.
    ///
    /// The rule below tests PAST TENSE and, for its first twenty types, tested it by asking
    /// whether the word ended in `-ed`. That proxy was right about those twenty and is wrong
    /// about English: `set`, `withdrawn`, `resent` and `sent` are past forms, and a
    /// compound like `assigned_to_group` carries its past form in the head verb. A guard
    /// that rejects them is not enforcing the rule it states -- it is enforcing a spelling.
    ///
    /// Listed as EXACT wire strings rather than relaxed into a smarter pattern, because the
    /// defect the rule exists to catch is a type slipping back into the audit vocabulary
    /// (`user.create`, `brand.delete`). An exception has to be typed out here, where a
    /// reviewer reads it beside the others, and `create` never will be.
    const IRREGULAR_PAST_FORMS: &[&str] = &[
        // `set` (set/set/set), for the upsert family: these writes install a value rather
        // than distinguishing a create from an update, and the type says so.
        "brand.set",
        "brand_asset.set",
        "client.allowed_scopes_set",
        "environment_secret.set",
        "environment_variable.set",
        "flow_target.set",
        "locale_bundle.set",
        "message_template.set",
        "organization.default_role_set",
        "claims_mapping.set",
        "challenge_component.set",
        "session_token_template.set",
        "signup_form.set",
        "step_up_policy.set",
        // `withdrawn` (withdraw/withdrew/withdrawn) and `resent` (resend/resent/resent).
        "invitation.resent",
        "message.resent",
        "project_grant.withdrawn",
        // Compounds whose PAST form is the head verb, followed by the preposition or particle
        // the fact needs: `assigned to`, not `assignment`; `signed in`, not `signin`.
        "org_role.assigned_to_group",
        "org_role.assigned_to_member",
        "org_role.unassigned_from_group",
        "org_role.unassigned_from_member",
        "user.signed_in",
    ];

    /// Every registered type is a dotted, `snake_case` token in the PAST TENSE.
    ///
    /// The past tense is the vocabulary rule that keeps this list from drifting back into
    /// the audit vocabulary, which is imperative (`user.create`). Asserted rather than
    /// documented, because that drift is the defect this module was born from.
    ///
    /// Regular forms are checked by their `-ed` ending; irregular ones are listed in
    /// [`IRREGULAR_PAST_FORMS`], which is where the reasoning for each lives.
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
                rest.ends_with("ed") || IRREGULAR_PAST_FORMS.contains(&wire.as_str()),
                "`{wire}` is not past tense. An event records what BECAME TRUE; the \
                 imperative form is the AUDIT vocabulary, and conflating the two is the \
                 defect this rule exists to prevent. If this IS a past form that simply \
                 does not end in -ed, add it to IRREGULAR_PAST_FORMS with the verb it comes \
                 from -- do not relax the ending test, which is what stops `create` here."
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

    /// Every `TENANT_SCOPED` entry names a type that is actually registered.
    ///
    /// The list is hand-written and keyed on the wire name, so a typo or a rename leaves an
    /// entry matching nothing. That failure is quiet in the wrong direction: the misspelled
    /// entry is inert, and the type it MEANT to name silently goes back to being treated as
    /// environment-scoped -- so a tenant-scoped producer would be required to name an
    /// environment it does not have. The reverse (a registered type missing from the list)
    /// fails loudly at its first emit, which is why only this direction needs a guard.
    #[test]
    fn every_tenant_scoped_entry_names_a_registered_type() {
        for wire in TENANT_SCOPED {
            assert!(
                REGISTERED.iter().any(|(name, _, _)| name == wire),
                "TENANT_SCOPED names `{wire}`, which is not a registered event type"
            );
        }
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
