// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-side config promotion: the deterministic DIFF, the dry-run PLAN, and
//! the transactional APPLY (issue #44).
//!
//! Promotion moves an environment's PROMOTABLE configuration from a source (a
//! canonical secret-free snapshot, issue #43) into a TARGET environment, in three
//! steps that are the whole flagship:
//!
//! - [`diff`] compares the source snapshot against the target's current
//!   configuration and produces a structured, per-resource difference (create,
//!   update, or delete, with the before and after values). It is a PURE function of
//!   its two inputs, so the same pair always yields the same diff (the determinism
//!   seam, invariant 3): the collection is ordered by resource type and then by the
//!   resource's stable natural key, never by insertion time or map iteration order.
//! - [`evaluate_plan`] turns a diff into a reviewable [`Plan`] with a STABLE,
//!   content-derived id. It RESOLVES every reference the source carries against the
//!   TARGET environment and FAILS CLOSED at plan time on an unresolved reference
//!   (issue #45), so an apply can never half-complete on a missing reference. The
//!   plan is a dry run: it computes and validates, and changes nothing.
//! - the APPLY is transactional and lives in the repository layer
//!   ([`crate::ScopedStore::acting`] -> `apply_promotion`), because it is the one
//!   step that mutates scoped tables and must write its audit trail in the SAME
//!   transaction. A plan captures the target's config REVISION
//!   ([`Plan::base_revision`]); apply re-derives that revision inside its
//!   transaction and fails with a structured DRIFT error if the target changed
//!   since the plan was computed, so promotion is safe without locking the tenant.
//!
//! # What promotes, and what never does
//!
//! The promotion engine operates on the promotable resource types that carry a
//! SCOPE-INDEPENDENT natural key and whose full promotable state travels in the
//! snapshot: resource servers (keyed by `audience`), DCR policies (keyed by
//! `name`), environment variables (keyed by `name`), brands (keyed by `slug`),
//! locale bundles (keyed by the BCP47 `locale` tag), and custom-journey versions
//! (keyed by `journey_id@version`). See [`PROMOTED_RESOURCE_TYPES`].
//! Environment-IDENTITY (the environment itself, its
//! signing keys, its issuer, its custom domains, its secrets' VALUES) is NEVER
//! diffed, planned, or applied: it is excluded from the snapshot by construction
//! (issue #41 classification, issue #43 export), so a promotion cannot copy one
//! environment's identity onto another. A secret VALUE never travels; a secret
//! REFERENCE does, and is resolved against the TARGET environment.
//!
//! OAuth clients are carried in the snapshot for export and review but are NOT
//! promoted by this engine: a client's identifier ([`crate::ClientId`]) EMBEDS its
//! `(tenant, environment)`, so a client's snapshot key cannot address the same
//! logical client across two environments. Promoting clients needs a stable,
//! scope-independent public client identity, a snapshot-format question owned by a
//! follow-up; this engine leaves the target's clients untouched rather than
//! silently minting divergent copies.
//!
//! # Branding, localization, and signup fields (issues #86, #87, #475)
//!
//! Brands and locale bundles ARE promoted: a brand's `slug` and a bundle's BCP47
//! `locale` tag are operator-authored strings that name the SAME logical resource in
//! every environment, so they address correctly across a promotion. Three per-brand
//! fields get per-type normalization, described on [`promoted_brand`]: the
//! per-CLIENT selection key is normalized away (it is a scope-embedded
//! [`crate::ClientId`], so it can never address the target's clients), the per-DOMAIN
//! selection key is CANONICALIZED through the same fold the management writer and the
//! selection matcher use (so a promoted host claim cannot slip past the per-scope unique
//! index that makes brand selection unambiguous), and the brand's
//! ASSET metadata travels by CONTENT REFERENCE (the sha256), sorted by kind, which the
//! apply resolves against bytes the TARGET already holds and refuses when it cannot.
//!
//! Signup forms (issue #87) are carried in the snapshot EXPORT but are NOT promoted,
//! for the SAME measured reason clients are not: a signup form's natural key IS an
//! authorize `client_id`, which the management write path parses with
//! [`crate::ClientId::parse_in_scope`], so the stored key is a scope-embedded id whose
//! payload contains the SOURCE environment's bytes. Promoting a form would insert a row
//! in the target keyed by a client that provably cannot exist there (a create of dead
//! config) and would delete the target's own form for its own client (the target-only
//! key looks like a source deletion), so promoting signup forms is not merely
//! incomplete, it is destructive. Unlike an unresolved variable or a missing asset
//! byte, there is NO action a target-environment operator could take to make such a
//! promotion resolve, so a fail-closed gate here would be a permanent block on every
//! cross-environment promotion rather than a safety net. Signup-form promotion is
//! therefore blocked on exactly the missing primitive client promotion is blocked on: a
//! stable, scope-independent public client identity. That is an owner-level
//! snapshot-format decision, not something this engine invents, and
//! `the_signup_form_key_is_a_scope_embedded_client_id_so_it_cannot_address_the_target`
//! in `tests/config_promotion.rs` measures the blocker rather than describing it.
//!
//! # Custom-journey versions and the per-environment activation gate (issue #92)
//!
//! A custom-journey version (issue #92) is an APPEND-ONLY, immutable artifact keyed
//! by `journey_id@version`: promotion carries the version DEFINITIONS, importing into
//! the target every `(journey_id, version)` the source has that the target lacks. A
//! version's artifact never changes, so a version already present with the SAME
//! artifact is a no-op and a version present with a DIFFERENT artifact for the same
//! key is an append-only CONFLICT the apply refuses (it never overwrites). A
//! target-only version is left untouched: promotion is additive, never a delete of a
//! target's own local history.
//!
//! Crucially, promotion carries the version definitions but NEVER moves the target's
//! ACTIVE PIN. A custom journey IS auth logic, so auto-activating a promoted pin would
//! silently change which journey authenticates users in the target environment. The
//! `pinned` flag in a [`crate::FlowVersionSnapshot`] is INFORMATIONAL (it records which
//! version was active in the SOURCE), never an apply instruction: the promoted
//! projection normalizes it away so it never enters the revision or the diff, and the
//! apply imports the definitions inert. The target keeps its own active pin until a
//! target-environment admin explicitly pins a version (the PR5 admin pin endpoint).
//! This mirrors the resolved #88 F7 posture: a promoted resource is secure-by-default
//! inert in the target until a target-env admin deliberately activates it.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::classification::ResourceType;
use crate::error::StoreError;
use crate::esv::Reference;
use crate::snapshot::{FlowVersionSnapshot, Snapshot, SnapshotResources};

/// Declare the promoted resource types ONCE and generate every form the engine needs
/// from that single list (issue #475): the [`PROMOTED_RESOURCE_TYPES`] array, its
/// length, and the CLOSED [`PromotedResourceType`] enum the transactional apply
/// dispatches on.
///
/// This is the DRIFT LOCK on the engine's hardest-to-see coupling. Before it, the
/// constant, the [`promoted_projection`], and the repository's apply dispatch were
/// three hand-maintained lists that nothing forced to agree, and all three had
/// silently diverged (`brand`, `locale_bundle` and `signup_form` sat in the snapshot
/// with an empty projection and no apply arm, so a promotion carried none of them).
/// Generating the enum from the same list makes every per-type dispatch an EXHAUSTIVE
/// match over it: adding a type here fails to COMPILE until its arm exists, which no
/// test could be forgotten to run. FOUR sites are locked that way, which is the whole
/// set of places a promoted type has to be wired:
///
/// - the repository's transactional apply dispatch (`apply_change`);
/// - [`diff`], which iterates [`PromotedResourceType::ALL`] and matches exhaustively
///   instead of calling one `diff_keyed` per type from a hand-written list;
/// - the repository's TARGET read (`read_promoted_snapshot`), which fills each promoted
///   collection from an exhaustive match instead of a hand-written struct literal;
/// - [`promoted_projection`], which is a struct literal (so a NEW SNAPSHOT field is a
///   compile error there) and is measured behaviourally besides.
///
/// The last two used to be the blind spot, and it was MEASURED rather than supposed: a
/// seventh type (`Connector`) added to this list, wired into [`promoted_projection`] and
/// given an apply arm but MISSING from `diff` and the target read compiled clean and
/// passed all of `--lib promotion` and all of `tests/config_promotion.rs`, because both
/// were hand-written lists that only per-type tests for today's six covered. Re-run that
/// mutation now and the build fails in both places, which is the only form of proof a
/// compile-time lock admits: a runtime test cannot observe a program that does not build.
///
/// The array's length is COUNTED from the declaration list rather than restated, so it
/// cannot be a number checked against itself. The remaining two agreements (the
/// projection carries exactly these types, and these types are a subset of the
/// snapshot's) are measured behaviourally by
/// `the_promoted_projection_carries_exactly_the_promoted_types` and
/// `the_promoted_types_are_a_subset_of_the_snapshot_types`, which read the SERIALIZED
/// projection keyed by [`ResourceType::as_str`] rather than a second hand-written list.
macro_rules! promoted_resource_types {
    ($( $(#[$doc:meta])* $variant:ident );+ $(;)?) => {
        /// The promotable resource types this engine diffs, plans, and applies.
        ///
        /// Each has a SCOPE-INDEPENDENT natural key (an `audience`, a `name`, a `slug`, a
        /// BCP47 tag, or a `journey_id@version`, never a scope-embedded identifier) and
        /// carries its full promotable state in the snapshot, so it round-trips across
        /// environments: applying a source then re-diffing the source against the target
        /// yields an empty diff.
        ///
        /// This is a strict SUBSET of [`crate::snapshot::SNAPSHOT_RESOURCE_TYPES`], which
        /// additionally carries the six types the engine does not apply: `client` and
        /// `signup_form` (both keyed by a scope-embedded [`crate::ClientId`], so their
        /// snapshot key cannot address the same logical resource in another environment),
        /// and `connector`, `org_connection`, `routing_rule` and `upstream_token_grant`
        /// (whose references must resolve against the target environment, a later slice).
        /// The module docs give the reasoning for each; the subset relation itself is
        /// enforced by `the_promoted_types_are_a_subset_of_the_snapshot_types`.
        pub const PROMOTED_RESOURCE_TYPES:
            [ResourceType; 0 $( + { let _ = stringify!($variant); 1 } )+] =
            [ $( ResourceType::$variant, )+ ];

        /// The CLOSED set of resource types the transactional apply dispatches on
        /// (issue #475): exactly [`PROMOTED_RESOURCE_TYPES`], as an enum, so the
        /// repository's dispatch is an EXHAUSTIVE match with no catch-all arm.
        ///
        /// [`ResourceType`] is `#[non_exhaustive]` and carries every management resource,
        /// so a dispatch over it needs a wildcard and can silently fall through for a
        /// newly promoted type. Narrowing to this generated enum first moves that failure
        /// from run time to COMPILE time.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PromotedResourceType {
            $( $(#[$doc])* $variant, )+
        }

        impl PromotedResourceType {
            /// Every promoted type, in declaration order: what the DIFF and the target READ
            /// iterate so their per-type wiring is an EXHAUSTIVE match rather than a
            /// hand-written call list (issue #475). Counted from the declaration list, like
            /// [`PROMOTED_RESOURCE_TYPES`], so the length cannot be a number checked against
            /// itself.
            pub const ALL: [PromotedResourceType; 0 $( + { let _ = stringify!($variant); 1 } )+] =
                [ $( PromotedResourceType::$variant, )+ ];

            /// Narrow a [`ResourceType`] to a promoted one, or [`None`] when this engine
            /// does not promote it. The apply turns [`None`] into a not-found rather than
            /// a silent skip.
            #[must_use]
            pub fn from_resource_type(value: ResourceType) -> Option<Self> {
                match value {
                    $( ResourceType::$variant => Some(Self::$variant), )+
                    _ => None,
                }
            }

            /// Widen back to the management-facing [`ResourceType`].
            #[must_use]
            pub fn as_resource_type(self) -> ResourceType {
                match self {
                    $( Self::$variant => ResourceType::$variant, )+
                }
            }
        }
    };
}

promoted_resource_types! {
    /// A registered resource server, keyed by `audience`.
    ResourceServer;
    /// A Dynamic Client Registration policy, keyed by `name`.
    DcrPolicy;
    /// A non-secret environment variable, keyed by `name`.
    Variable;
    /// A per-environment brand, keyed by `slug` (issue #86).
    Brand;
    /// A per-environment locale bundle, keyed by its BCP47 tag (issue #86, PR 2).
    LocaleBundle;
    /// An append-only custom-journey version, keyed by `journey_id@version` (issue #92).
    FlowVersion;
    /// A per-environment message template, keyed by `kind/locale` (issue #111).
    MessageTemplate;
}

/// Whether a resource change creates, updates, or deletes a target resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The resource exists in the source but not the target: apply INSERTS it.
    Create,
    /// The resource exists in both but differs: apply OVERWRITES the target's to
    /// match the source.
    Update,
    /// The resource exists in the target but not the source: apply REMOVES it.
    /// Deletes are explicit; apply never removes a target resource the plan did not
    /// enumerate.
    Delete,
}

impl ChangeKind {
    /// The stable wire string (`create`, `update`, `delete`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Create => "create",
            ChangeKind::Update => "update",
            ChangeKind::Delete => "delete",
        }
    }
}

/// One entry in a [`ConfigDiff`]: a single promotable resource that must be
/// created, updated, or deleted in the target to make it match the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceChange {
    /// The promotable resource type this change acts on (one of
    /// [`PROMOTED_RESOURCE_TYPES`]).
    pub resource_type: ResourceType,
    /// The resource's stable natural key (an `audience` or a `name`): what the
    /// change is addressed by, and what apply matches the target row on.
    pub key: String,
    /// Whether the change creates, updates, or deletes the resource.
    pub kind: ChangeKind,
    /// The target's current value, present for an update or a delete (the row that
    /// will be overwritten or removed), absent for a create.
    pub before: Option<serde_json::Value>,
    /// The source's value, present for a create or an update (the value the target
    /// will carry), absent for a delete.
    pub after: Option<serde_json::Value>,
}

impl ResourceChange {
    /// This change rendered as a machine-readable JSON object (the plan's wire
    /// form): the resource type, the natural key, the change kind, and the before
    /// and after values.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "resource_type".to_owned(),
            serde_json::Value::String(self.resource_type.as_str().to_owned()),
        );
        map.insert(
            "key".to_owned(),
            serde_json::Value::String(self.key.clone()),
        );
        map.insert(
            "change".to_owned(),
            serde_json::Value::String(self.kind.as_str().to_owned()),
        );
        map.insert(
            "before".to_owned(),
            self.before.clone().unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "after".to_owned(),
            self.after.clone().unwrap_or(serde_json::Value::Null),
        );
        serde_json::Value::Object(map)
    }
}

/// The structured difference between a source snapshot and a target environment's
/// current configuration: the ordered set of per-resource changes apply will make.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigDiff {
    changes: Vec<ResourceChange>,
}

impl ConfigDiff {
    /// The ordered changes. Ordering is deterministic: by resource type (in
    /// [`PROMOTED_RESOURCE_TYPES`] order) and then by the resource's natural key.
    #[must_use]
    pub fn changes(&self) -> &[ResourceChange] {
        &self.changes
    }

    /// Whether the target already matches the source (no changes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The number of changes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// This diff as a machine-readable JSON array of change objects.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(self.changes.iter().map(ResourceChange::to_json).collect())
    }
}

/// Compute the structured difference between a source snapshot and a target
/// snapshot (issue #44), for the promotable types this engine manages.
///
/// A resource present in the source but not the target is a [`ChangeKind::Create`];
/// one present in both whose value differs is a [`ChangeKind::Update`]; one present
/// in the target but not the source is a [`ChangeKind::Delete`]. A resource present
/// in both with an identical value produces no change. The result is deterministic:
/// changes are ordered by resource type and then by natural key, drawn from a
/// [`BTreeMap`] so neither map iteration order nor insertion time can leak in.
///
/// Only [`PROMOTED_RESOURCE_TYPES`] are compared; any `client` in either snapshot
/// is ignored (see the module docs), so the target's clients are never touched.
///
/// The per-type wiring is an EXHAUSTIVE match over [`PromotedResourceType`], walked in
/// [`PromotedResourceType::ALL`] (declaration) order, NOT a hand-written call list:
/// promoting a new resource type makes this match non-exhaustive and the crate fails to
/// COMPILE until the type is diffed. Before that lock, a type could be wired into the
/// projection and the apply and silently left out of the diff, so a promotion carried it
/// in the revision but enumerated no change for it.
#[must_use]
pub fn diff(source: &Snapshot, target: &Snapshot) -> ConfigDiff {
    let mut changes = Vec::new();
    for promoted in PromotedResourceType::ALL {
        match promoted {
            PromotedResourceType::ResourceServer => diff_keyed(
                ResourceType::ResourceServer,
                &keyed_resource_servers(&source.resources),
                &keyed_resource_servers(&target.resources),
                &mut changes,
            ),
            PromotedResourceType::DcrPolicy => diff_keyed(
                ResourceType::DcrPolicy,
                &keyed_dcr_policies(&source.resources),
                &keyed_dcr_policies(&target.resources),
                &mut changes,
            ),
            PromotedResourceType::Variable => diff_keyed(
                ResourceType::Variable,
                &keyed_variables(&source.resources),
                &keyed_variables(&target.resources),
                &mut changes,
            ),
            PromotedResourceType::Brand => diff_keyed(
                ResourceType::Brand,
                &keyed_brands(&source.resources),
                &keyed_brands(&target.resources),
                &mut changes,
            ),
            PromotedResourceType::MessageTemplate => diff_keyed(
                ResourceType::MessageTemplate,
                &keyed_message_templates(&source.resources),
                &keyed_message_templates(&target.resources),
                &mut changes,
            ),
            PromotedResourceType::LocaleBundle => diff_keyed(
                ResourceType::LocaleBundle,
                &keyed_locale_bundles(&source.resources),
                &keyed_locale_bundles(&target.resources),
                &mut changes,
            ),
            // Append-only, so this one is NOT `diff_keyed`: it never emits a delete.
            PromotedResourceType::FlowVersion => diff_flow_versions(
                &keyed_flow_versions(&source.resources),
                &keyed_flow_versions(&target.resources),
                &mut changes,
            ),
        }
    }
    ConfigDiff { changes }
}

/// Diff one resource type's source and target maps (each keyed by natural key),
/// appending the changes in natural-key order.
fn diff_keyed(
    resource_type: ResourceType,
    source: &BTreeMap<String, serde_json::Value>,
    target: &BTreeMap<String, serde_json::Value>,
    changes: &mut Vec<ResourceChange>,
) {
    // Iterate the union of keys in sorted order. A BTreeMap yields sorted keys, so
    // stepping the two in a merge over the union is deterministic.
    let mut keys: Vec<&String> = source.keys().chain(target.keys()).collect();
    keys.sort_unstable();
    keys.dedup();
    for key in keys {
        match (source.get(key), target.get(key)) {
            (Some(after), None) => changes.push(ResourceChange {
                resource_type,
                key: key.clone(),
                kind: ChangeKind::Create,
                before: None,
                after: Some(after.clone()),
            }),
            (None, Some(before)) => changes.push(ResourceChange {
                resource_type,
                key: key.clone(),
                kind: ChangeKind::Delete,
                before: Some(before.clone()),
                after: None,
            }),
            (Some(after), Some(before)) if after != before => changes.push(ResourceChange {
                resource_type,
                key: key.clone(),
                kind: ChangeKind::Update,
                before: Some(before.clone()),
                after: Some(after.clone()),
            }),
            // Present in both and identical, or absent from both: no change.
            _ => {}
        }
    }
}

/// Diff a snapshot's custom-journey versions (issue #92), ADDITIVELY: a version is
/// APPEND-ONLY and immutable, so this only ever emits creates and (artifact-mismatch)
/// updates, NEVER a delete.
///
/// Each map is keyed by `journey_id@version` with the version's ARTIFACT as its value
/// (the pin is deliberately excluded, per the activation gate). A key present in the
/// source but not the target is a [`ChangeKind::Create`] (import the version); a key
/// present in both whose artifact DIFFERS is a [`ChangeKind::Update`], which the apply
/// refuses as an append-only conflict (a version's artifact never changes, so this is
/// never an overwrite). A key present in both with an identical artifact produces no
/// change. A key present only in the TARGET is IGNORED (never a delete): promotion
/// never destroys a target's own local version history. Source keys are drawn from a
/// [`BTreeMap`] so the emitted order is deterministic.
fn diff_flow_versions(
    source: &BTreeMap<String, serde_json::Value>,
    target: &BTreeMap<String, serde_json::Value>,
    changes: &mut Vec<ResourceChange>,
) {
    for (key, after) in source {
        match target.get(key) {
            None => changes.push(ResourceChange {
                resource_type: ResourceType::FlowVersion,
                key: key.clone(),
                kind: ChangeKind::Create,
                before: None,
                after: Some(after.clone()),
            }),
            Some(before) if before != after => changes.push(ResourceChange {
                resource_type: ResourceType::FlowVersion,
                key: key.clone(),
                kind: ChangeKind::Update,
                before: Some(before.clone()),
                after: Some(after.clone()),
            }),
            // Present in both with an identical artifact: append-only no-op.
            _ => {}
        }
    }
}

/// The custom-journey versions of a snapshot, keyed by `journey_id@version`, with the
/// version's ARTIFACT as the value (issue #92).
///
/// The pin is NOT part of the value: the activation gate keeps a promoted pin out of
/// the diff and the revision, so promotion carries the version definitions but never
/// moves the target's active pin. The natural key joins the journey id and the version
/// with `@`; the version is numeric, so `rsplit_once('@')` recovers the pair even were
/// a journey id itself to carry `@`.
fn keyed_flow_versions(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .flow_version
        .iter()
        .map(|version| {
            (
                flow_version_key(&version.journey_id, version.version),
                version.artifact.clone(),
            )
        })
        .collect()
}

/// The `journey_id@version` natural key of a custom-journey version (issue #92).
#[must_use]
/// The natural key of a message template: its `kind` and `locale`, joined by `/` (issue #111).
///
/// Both halves are ESCAPED rather than joined raw. `Locale::new` normalizes a tag but does not
/// constrain its character set, and `message_templates.kind` carries no CHECK, so neither half
/// is guaranteed to be free of the separator: a raw join would make `a/b` + `c` and `a` + `b/c`
/// the same key, and two different templates would diff as one. `flow_version_key` can join raw
/// only because its tail is an integer.
pub(crate) fn message_template_key(kind: &str, locale: &str) -> String {
    format!(
        "{}/{}",
        escape_key_segment(kind),
        escape_key_segment(locale)
    )
}

/// Escape `\` and `/` in one half of a [`message_template_key`], so the separator that survives
/// is only ever the one this function put there.
fn escape_key_segment(segment: &str) -> String {
    segment.replace('\\', "\\\\").replace('/', "\\/")
}

/// Recover the `(kind, locale)` pair from a [`message_template_key`] (issue #111).
///
/// Splits at the one UNESCAPED `/`, then unescapes each half. Returns [`None`] for a key with no
/// unescaped separator or with a trailing lone `\` (neither is produced by
/// [`message_template_key`]).
#[must_use]
pub(crate) fn split_message_template_key(key: &str) -> Option<(String, String)> {
    let mut kind = String::new();
    let mut chars = key.chars();
    // Walk to the separator, consuming escapes so an escaped `/` cannot end the first half.
    let separator_found = loop {
        match chars.next() {
            None => break false,
            Some('/') => break true,
            Some('\\') => kind.push(chars.next()?),
            Some(other) => kind.push(other),
        }
    };
    if !separator_found {
        return None;
    }
    let mut locale = String::new();
    loop {
        match chars.next() {
            None => break,
            Some('\\') => locale.push(chars.next()?),
            Some(other) => locale.push(other),
        }
    }
    Some((kind, locale))
}

/// The message templates of a snapshot, keyed by `kind/locale`.
fn keyed_message_templates(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .message_template
        .iter()
        .map(|template| {
            (
                message_template_key(&template.kind, &template.locale),
                serde_json::to_value(template).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

pub(crate) fn flow_version_key(journey_id: &str, version: i32) -> String {
    format!("{journey_id}@{version}")
}

/// Recover the `(journey_id, version)` pair from a [`flow_version_key`] (issue #92):
/// the version is the numeric tail after the LAST `@`, so a journey id carrying `@`
/// still round-trips. Returns [`None`] for a key whose tail is not an integer (never
/// produced by [`flow_version_key`]).
#[must_use]
pub(crate) fn parse_flow_version_key(key: &str) -> Option<(String, i32)> {
    let (journey_id, version) = key.rsplit_once('@')?;
    let version: i32 = version.parse().ok()?;
    Some((journey_id.to_owned(), version))
}

/// The resource servers of a snapshot, keyed by `audience`.
fn keyed_resource_servers(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .resource_server
        .iter()
        .map(|server| {
            (
                server.audience.clone(),
                serde_json::to_value(server).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The DCR policies of a snapshot, keyed by `name`.
fn keyed_dcr_policies(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .dcr_policy
        .iter()
        .map(|policy| {
            (
                policy.name.clone(),
                serde_json::to_value(policy).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The brands of a snapshot, keyed by `slug`, each value the NORMALIZED promotable
/// brand (issue #475).
///
/// The value is [`promoted_brand`], the same normalization the revision is computed
/// over, so the diff and the revision can never disagree about what a brand's
/// promotable state is: one function decides, both callers read it.
fn keyed_brands(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .brand
        .iter()
        .map(|brand| {
            (
                brand.slug.clone(),
                serde_json::to_value(promoted_brand(brand)).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The locale bundles of a snapshot, keyed by their BCP47 `locale` tag.
fn keyed_locale_bundles(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .locale_bundle
        .iter()
        .map(|bundle| {
            (
                bundle.locale.clone(),
                serde_json::to_value(bundle).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The environment variables of a snapshot, keyed by `name`.
fn keyed_variables(resources: &SnapshotResources) -> BTreeMap<String, serde_json::Value> {
    resources
        .variable
        .iter()
        .map(|variable| {
            (
                variable.name.clone(),
                serde_json::to_value(variable).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// The canonical REVISION of a snapshot's promotable configuration: a content hash
/// over exactly the [`PROMOTED_RESOURCE_TYPES`] projection (issue #44).
///
/// Two snapshots with the same promotable configuration hash to the same revision,
/// and any change to a promoted resource changes it. The `client` set is EXCLUDED
/// (clients are not promoted, so their per-environment divergence must not perturb
/// the revision), so a target's revision reflects only what promotion manages. This
/// is the optimistic-concurrency token a plan captures and apply re-checks for
/// drift.
///
/// # Errors
///
/// [`StoreError::Database`] wrapping a canonicalization fault (not reachable for a
/// well-formed snapshot).
pub fn revision(snapshot: &Snapshot) -> Result<String, StoreError> {
    let bytes = promoted_projection(snapshot).to_canonical_bytes()?;
    let digest = Sha256::digest(&bytes);
    Ok(hex_lower(&digest))
}

/// The NORMALIZED promotable projection of one brand (issue #475): what a promotion
/// actually carries for a brand, as opposed to what the snapshot EXPORT records.
///
/// One field is normalized AWAY, one is normalized IN PLACE, and one is re-ORDERED.
///
/// The field normalized away is the brand's per-CLIENT selection
/// key. `BrandSnapshot::client_id` is an authorize `client_id`, which is a
/// [`crate::ClientId`]: a scope-embedded identifier whose payload contains the SOURCE
/// environment's bytes (`ClientId::parse_in_scope` under the target scope is a uniform
/// not-found for it, by construction). Carrying it would do two bad things at once. It
/// would write a selection key into the target that `select_brand`'s tier-1
/// per-client match can never hit, so the promoted value is dead config; and, worse,
/// it would OVERWRITE a target-environment admin's own per-client selection with that
/// dead value, silently changing which brand a named relying party renders in the
/// target. That is the same hazard the custom-journey `pinned` flag is normalized for
/// (see the module docs): a per-environment activation key must never ride a
/// promotion. The `brands_client_id_idx` partial unique index makes the key
/// per-environment-exclusive too, so a carried key is also a latent unique-violation.
/// The target-env admin sets the per-client selection deliberately, and a promotion
/// leaves it alone.
///
/// Everything else IS the brand's promotable definition and travels as authored:
///
/// - `is_default` travels. Unlike a journey pin it gates no auth logic (it selects
///   which cosmetic brand renders when nothing more specific matches), and a promotion
///   that could not carry it would land every brand inert in the target, which is the
///   opposite of the promise. The one-default-per-scope partial unique index is
///   respected by the apply, which demotes any other default first, exactly as
///   `Brands::set` does.
/// - `host_pattern` travels as authored, CANONICALIZED through
///   [`crate::brand::canonicalize_host`] (the field normalized in place). It is an
///   operator-authored hostname, not a machine-minted scope-embedded id, so an operator
///   CAN author the same value in two environments; where they differ, the shipped
///   `BrandSnapshot::host_pattern` contract already says the target-env operator adjusts
///   it, and the change is visible in the diff.
///
///   Folding it here is not cosmetic, it is the brand-selection UNIQUENESS invariant.
///   `brands_host_pattern_idx` is a partial unique index on the RAW column, and the
///   management writer canonicalizes at ingest so the index sees one spelling per host.
///   A promotion is the SECOND writer of that column, so it must fold on the same
///   function or a promoted `LOGIN.Acme.Test:8443` would sit beside a stored
///   `login.acme.test` under a unique index that cannot see they are the same host,
///   while `select_brand` (which normalizes both sides before comparing) resolves BOTH
///   for the same request. That would falsify "first match is also the only match".
///   Canonicalizing HERE rather than only at the apply's bind is what makes the
///   promotion converge: the diff and the revision read this projection, so an apply
///   that stored the folded form while the diff read the raw one would re-propose the
///   same update on every plan, forever.
///
///   What carrying the field can DO to the target is stated precisely, because the
///   obvious summary is wrong. It can de-select a per-host brand (the fallback is the
///   env default), it can activate one (a target brand that claimed no host, or claimed
///   a different one, can end up claiming a host the source names), and it can
///   RE-POINT a host: a source that moves a claim from one slug to another moves which
///   brand renders for that hostname in the target. All three are enumerated in the
///   diff before an operator approves the plan, which is the actual safety property.
///   The field is cosmetic selection, not auth logic, so unlike a journey pin it is not
///   gated inert.
/// - `assets` travel as by-reference METADATA (kind, sniffed content type, sha256,
///   size), SORTED BY KIND (the re-ordered field). The bytes never enter the snapshot
///   document; the apply resolves each asset's sha256 against bytes the TARGET already
///   holds and REFUSES the whole promotion when it cannot, so a promotion can never
///   leave the target with metadata pointing at bytes it does not have, and can never
///   serve the source's bytes. The sort exists because the TARGET read orders a brand's
///   assets by kind while a hand-authored document may list them in any order, and the
///   diff compares the whole serialized element: without it a document listing
///   `[logo, favicon]` would produce an Update on EVERY plan and the promotion would
///   never reach [`PromotionOutcome::NoOp`].
#[must_use]
fn promoted_brand(brand: &crate::snapshot::BrandSnapshot) -> crate::snapshot::BrandSnapshot {
    let mut assets = brand.assets.clone();
    assets.sort_by(|a, b| a.kind.cmp(&b.kind));
    crate::snapshot::BrandSnapshot {
        slug: brand.slug.clone(),
        is_default: brand.is_default,
        product_name: brand.product_name.clone(),
        show_wordmark: brand.show_wordmark,
        brand_token: brand.brand_token.clone(),
        tokens: brand.tokens.clone(),
        tokens_dark: brand.tokens_dark.clone(),
        slots: brand.slots.clone(),
        // The selection-uniqueness fold: see the doc comment above.
        host_pattern: promoted_host_pattern(brand.host_pattern.as_deref()),
        // The per-environment activation gate: see the doc comment above.
        client_id: None,
        assets,
    }
}

/// The CANONICAL form of a promoted brand's `host_pattern` (issue #475): the single
/// spelling the diff, the revision, and the apply's bind all use.
///
/// One function so the three can never disagree. [`crate::brand::canonicalize_host`]
/// is the same fold the management writer applies at ingest and the same one the OIDC
/// selection matcher normalizes a request Host through, so a promoted host key lands in
/// the form the per-scope unique index and the matcher both key on. An empty or
/// whitespace-only pattern folds to [`None`]: there is no host to claim.
#[must_use]
pub(crate) fn promoted_host_pattern(raw: Option<&str>) -> Option<String> {
    raw.and_then(crate::brand::canonicalize_host)
}

/// The snapshot projected to exactly the promoted resource types (the `client` and
/// `connector` sets emptied), so a revision and a round-trip diff ignore their
/// non-promoted divergence between environments.
//
// `connector` (issue #75) is carried in the config-snapshot EXPORT (it is a
// promotable definition, diffable and committable), but the transactional promotion
// ENGINE does not yet apply it: promoting a connector requires resolving its upstream
// client-secret reference against the target environment's secret store, which is a
// later slice. It is therefore emptied here exactly like `client`, so the promotion
// revision stays consistent (source projection and target read both omit it) rather
// than the engine attempting an apply it cannot complete.
fn promoted_projection(snapshot: &Snapshot) -> Snapshot {
    Snapshot {
        schema_version: snapshot.schema_version.clone(),
        resources: SnapshotResources {
            client: Vec::new(),
            resource_server: snapshot.resources.resource_server.clone(),
            dcr_policy: snapshot.resources.dcr_policy.clone(),
            variable: snapshot.resources.variable.clone(),
            connector: Vec::new(),
            // Org connections and routing rules (issue #77) are not promoted by the
            // transactional engine yet (their organization / connector references must
            // resolve against the target environment, a later slice), so the promoted
            // projection omits them exactly like `connector`.
            org_connection: Vec::new(),
            routing_rule: Vec::new(),
            // Upstream-token grants (issue #77) are likewise not promoted by the engine
            // yet (a grant's client / org-connection references must resolve against the
            // target env, a later slice), so the promoted projection omits them.
            upstream_token_grant: Vec::new(),
            // Brands (issue #86) ARE promoted (issue #475): the whole branding DEFINITION
            // travels, NORMALIZED through `promoted_brand`, which drops only the
            // per-CLIENT selection key (a scope-embedded `ClientId` that cannot address
            // the target's clients). See that function for the full per-field reasoning.
            brand: snapshot
                .resources
                .brand
                .iter()
                .map(promoted_brand)
                .collect(),
            // Locale bundles (issue #86, PR 2) ARE promoted (issue #475) and need no
            // normalization: a bundle carries only its BCP47 tag, its env-default flag,
            // and its plain-text entries map. No field is a scope-embedded identifier and
            // no field gates auth (the default locale selects a language, not a journey),
            // so the whole definition travels as authored.
            locale_bundle: snapshot.resources.locale_bundle.clone(),
            // Message templates (issue #111) ARE promoted and need no normalization. Every
            // field is promotable DEFINITION -- a kind, a BCP47 locale, the subject and
            // bodies, and the lock flag -- and none is a scope-embedded identifier. That is
            // exactly what a signup form lacks: its key is a scope-embedded `ClientId`, while
            // a template's `(kind, locale)` is two plain strings that mean the same thing in
            // every environment. The snapshot carries the ENVIRONMENT level only, so a tenant
            // default and a per-organization override cannot travel here.
            message_template: snapshot.resources.message_template.clone(),
            // Signup forms (issue #87) are carried in the EXPORT but are NOT promoted. This
            // is a DELIBERATE, MEASURED exclusion, not a later slice, and the distinction
            // matters: the other omissions above are work that is merely unwritten, while
            // this one CANNOT be written until a missing primitive exists. A form's natural
            // key is an authorize `client_id`, a scope-embedded `ClientId`, so it cannot
            // address the same logical client in another environment. Promoting one would
            // create a row for a client that provably cannot exist in the target AND delete
            // the target's own form (its client's key looks like a source deletion), so it
            // is not merely incomplete, it is destructive; and unlike a missing variable or
            // a missing asset byte there is NO action a target operator could take to make
            // it resolve, so even a fail-closed gate would be a permanent block rather than
            // a safety net. The blocker is precisely the absence of a STABLE,
            // SCOPE-INDEPENDENT PUBLIC CLIENT IDENTITY, the same primitive that blocks
            // `client` promotion, and minting one is an owner-level snapshot-format
            // decision rather than something this engine invents. The projection therefore
            // empties them exactly like `client`, which is excluded for the identical
            // reason, and the signup-form test in tests/config_promotion.rs measures the
            // blocker (the source key does not parse in the target scope) rather than
            // describing it.
            signup_form: Vec::new(),
            // Custom-journey versions (issue #92) ARE promoted by the transactional engine: the
            // append-only version DEFINITIONS travel and are reconstructed in the target. The
            // projection carries each version's `(journey_id, version, artifact)` but NORMALIZES
            // its `pinned` flag to `false` (the per-environment activation gate): the pin records
            // which version was active in the SOURCE and must never enter the promotable revision
            // or the diff, so a promoted pin can never silently swap the target's active auth
            // journey. Activation stays a deliberate target-env admin action. Normalizing here (and
            // in the target read, which reports every version unpinned) keeps the revision
            // pin-independent on both sides.
            flow_version: snapshot
                .resources
                .flow_version
                .iter()
                .map(|version| FlowVersionSnapshot {
                    journey_id: version.journey_id.clone(),
                    version: version.version,
                    artifact: version.artifact.clone(),
                    pinned: false,
                })
                .collect(),
        },
    }
}

/// Lowercase hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Collect every whole-token reference embedded in a snapshot's PROMOTED
/// configuration, deduplicated and ordered deterministically by rendered token
/// (issue #45).
///
/// A field value is a reference only when its WHOLE value parses as a `${var:NAME}`
/// or `${secret:NAME}` token (the same rule the store applies elsewhere); a literal
/// that merely contains the syntax is not a reference and is ignored. The plan step
/// checks each collected reference resolves in the target and fails closed on a
/// miss.
#[must_use]
pub fn collect_references(snapshot: &Snapshot) -> Vec<Reference> {
    let value =
        serde_json::to_value(promoted_projection(snapshot)).unwrap_or(serde_json::Value::Null);
    let mut found: Vec<Reference> = Vec::new();
    collect_reference_strings(&value, &mut found);
    // Deduplicate by rendered token and order deterministically.
    found.sort_by_key(Reference::render);
    found.dedup_by(|a, b| a.render() == b.render());
    found
}

/// Recursively collect reference tokens from the string leaves of `value`.
fn collect_reference_strings(value: &serde_json::Value, found: &mut Vec<Reference>) {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(reference) = Reference::parse(text) {
                found.push(reference);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_reference_strings(item, found);
            }
        }
        serde_json::Value::Object(map) => {
            for child in map.values() {
                collect_reference_strings(child, found);
            }
        }
        _ => {}
    }
}

/// A per-item reason a plan could not be built (issue #44). A plan step surfaces
/// EVERY failing item at once so the caller learns all problems from one dry run,
/// exactly like snapshot validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A reference the source carries does not resolve in the TARGET environment
    /// (issue #45): no variable or secret of that name exists there. Failing here
    /// is what keeps an apply from ever half-completing on a missing reference.
    UnresolvedReference(Reference),
    /// A snapshot could not be canonicalized to compute a revision (not reachable
    /// for a well-formed snapshot).
    Serialization,
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlanError::UnresolvedReference(reference) => write!(
                f,
                "reference {} does not resolve in the target environment",
                reference.render()
            ),
            PlanError::Serialization => f.write_str("snapshot could not be canonicalized"),
        }
    }
}

impl std::error::Error for PlanError {}

/// A reviewable promotion plan (issue #44): the exact set of changes an apply will
/// make, with a stable id and the optimistic-concurrency revisions.
///
/// A plan is an addressable, machine-readable and human-renderable artifact. It
/// carries no secret material (the diff's before/after are drawn from the
/// secret-free snapshots), so it is safe to persist, review, and hand to a
/// different authorized actor to apply later.
#[allow(
    clippy::struct_field_names,
    reason = "plan_id is the stable, wire-facing name of the plan's identifier; \
              renaming it to drop the type prefix would obscure the contract"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    plan_id: String,
    base_revision: String,
    result_revision: String,
    diff: ConfigDiff,
    references: Vec<Reference>,
}

impl Plan {
    /// The stable, content-derived plan id: a hash of the base and result
    /// revisions. Identical inputs (the same source promoted onto the same target
    /// state) yield the same id, so the plan id is deterministic (invariant 3).
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// The target's promotable-config revision AT PLAN TIME (the optimistic
    /// concurrency token). Apply proceeds only if the target still carries this
    /// revision; otherwise it fails with a drift error and changes nothing.
    #[must_use]
    pub fn base_revision(&self) -> &str {
        &self.base_revision
    }

    /// The target's promotable-config revision AFTER a successful apply: the
    /// revision of the source's promoted configuration. When the target already
    /// carries this revision, apply is a no-op (idempotent re-apply).
    #[must_use]
    pub fn result_revision(&self) -> &str {
        &self.result_revision
    }

    /// The structured diff this plan will apply.
    #[must_use]
    pub fn diff(&self) -> &ConfigDiff {
        &self.diff
    }

    /// The references the source carries, each verified to resolve in the target at
    /// plan time.
    #[must_use]
    pub fn references(&self) -> &[Reference] {
        &self.references
    }

    /// The plan rendered as a machine-readable JSON object (its wire form): the
    /// plan id, both revisions, the resolved references, and the diff.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "plan_id".to_owned(),
            serde_json::Value::String(self.plan_id.clone()),
        );
        map.insert(
            "base_revision".to_owned(),
            serde_json::Value::String(self.base_revision.clone()),
        );
        map.insert(
            "result_revision".to_owned(),
            serde_json::Value::String(self.result_revision.clone()),
        );
        map.insert(
            "references".to_owned(),
            serde_json::Value::Array(
                self.references
                    .iter()
                    .map(|reference| serde_json::Value::String(reference.render()))
                    .collect(),
            ),
        );
        map.insert("diff".to_owned(), self.diff.to_json());
        serde_json::Value::Object(map)
    }
}

/// The result of a successful [`crate::ActingStore::apply_promotion`] (issue #44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutcome {
    /// The plan was applied: the target now matches the source's promotable
    /// configuration. Carries the exact diff that was applied.
    Applied(ConfigDiff),
    /// The target already matched the source's promotable configuration, so apply
    /// changed nothing (idempotent re-apply). No audit row is written.
    NoOp,
}

/// Why a transactional promotion apply failed (issue #44). On ANY of these, the
/// apply transaction rolls back completely: the target is left byte-for-byte as it
/// was, with no partial promotion.
#[derive(Debug)]
pub enum PromotionApplyError {
    /// The target's promotable configuration changed since the plan was computed
    /// (its revision no longer matches the plan's `base_revision`): the plan is
    /// stale. Apply changes nothing; the caller re-plans against the current target.
    Drift {
        /// The revision the plan captured at plan time (`base_revision`).
        expected: String,
        /// The target's actual current revision.
        found: String,
    },
    /// A reference the source carries does not resolve in the TARGET environment at
    /// apply time (issue #45): a variable or secret it names is absent. Because
    /// secrets are environment-identity and outside the promotable revision, a
    /// secret can vanish between plan and apply WITHOUT changing the revision, so
    /// apply re-checks and fails closed rather than half-completing.
    UnresolvedReference(Reference),
    /// The source carries a custom-journey version whose `(journey_id, version)` already
    /// exists in the TARGET with a DIFFERENT artifact (issue #92): a custom-journey version
    /// is APPEND-ONLY and immutable, so its artifact never changes. Apply refuses the
    /// conflict and changes nothing rather than overwriting the target's existing version.
    /// The operator re-authors the divergent version under a NEW version number instead.
    FlowVersionArtifactConflict {
        /// The author-facing journey id whose version conflicts.
        journey_id: String,
        /// The version number that exists in the target with a different artifact.
        version: i32,
    },
    /// The source carries a brand ASSET whose bytes the TARGET does not hold (issue
    /// #475). A snapshot is a small, diffable TEXT document and deliberately carries an
    /// asset by CONTENT REFERENCE (its sha256), never as an inline binary; the apply
    /// therefore materializes an asset only from bytes already present in the target
    /// scope with that exact digest. When no such bytes exist, there is no source for
    /// them at all, so the apply FAILS CLOSED and the whole transaction rolls back
    /// rather than writing metadata that points at bytes the target does not have (or,
    /// worse, leaving the target serving a different image under the promoted digest).
    ///
    /// The operator's remedy is to upload the asset to the TARGET environment through
    /// the management asset endpoint (creating the brand there first if needed) and
    /// re-plan; the promotion then resolves the digest and binds it to the promoted
    /// brand.
    BrandAssetBytesUnavailable {
        /// The brand slug whose asset could not be resolved.
        slug: String,
        /// The asset kind (`logo` or `favicon`).
        kind: String,
        /// The lowercase hex sha256 the source's metadata names, absent from the target.
        sha256: String,
    },
    /// A persistence fault while applying (the transaction rolled back).
    Store(StoreError),
}

impl From<StoreError> for PromotionApplyError {
    fn from(source: StoreError) -> Self {
        PromotionApplyError::Store(source)
    }
}

impl From<sqlx::Error> for PromotionApplyError {
    fn from(source: sqlx::Error) -> Self {
        PromotionApplyError::Store(StoreError::from(source))
    }
}

impl core::fmt::Display for PromotionApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PromotionApplyError::Drift { expected, found } => write!(
                f,
                "target drifted since the plan was computed (expected revision {expected}, \
                 found {found})"
            ),
            PromotionApplyError::UnresolvedReference(reference) => write!(
                f,
                "reference {} does not resolve in the target environment at apply time",
                reference.render()
            ),
            PromotionApplyError::FlowVersionArtifactConflict {
                journey_id,
                version,
            } => write!(
                f,
                "custom-journey version {journey_id}@{version} already exists in the target with a \
                 different artifact; a version is append-only and its artifact never changes \
                 (re-author the change under a new version number)"
            ),
            PromotionApplyError::BrandAssetBytesUnavailable { slug, kind, sha256 } => write!(
                f,
                "brand {slug} carries a {kind} asset with digest {sha256}, whose bytes the \
                 target environment does not hold; a snapshot carries an asset by content \
                 reference, never as inline bytes, so upload the asset to the target \
                 environment and re-plan"
            ),
            PromotionApplyError::Store(source) => write!(f, "promotion apply failed: {source}"),
        }
    }
}

impl std::error::Error for PromotionApplyError {}

/// Evaluate a promotion plan from a source and target snapshot (issue #44), PURELY:
/// the reference existence check is INJECTED as `resolves`, so the plan logic is
/// database-free and exhaustively unit-testable, and the repository layer supplies
/// a `resolves` backed by the target environment's store.
///
/// Returns the [`Plan`] on success, or EVERY [`PlanError`] found (an unresolved
/// reference per item) so the caller fixes them all from one dry run. `resolves`
/// answers whether a reference exists in the target environment; a reference it
/// rejects becomes a [`PlanError::UnresolvedReference`].
///
/// # Errors
///
/// A non-empty `Vec<PlanError>` when any reference is unresolved or a snapshot
/// cannot be canonicalized.
pub fn evaluate_plan<F>(
    source: &Snapshot,
    target: &Snapshot,
    resolves: F,
) -> Result<Plan, Vec<PlanError>>
where
    F: Fn(&Reference) -> bool,
{
    let mut errors = Vec::new();

    let base_revision = if let Ok(value) = revision(target) {
        value
    } else {
        errors.push(PlanError::Serialization);
        String::new()
    };
    let result_revision = if let Ok(value) = revision(source) {
        value
    } else {
        errors.push(PlanError::Serialization);
        String::new()
    };

    let references = collect_references(source);
    for reference in &references {
        if !resolves(reference) {
            errors.push(PlanError::UnresolvedReference(reference.clone()));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let diff = diff(source, target);
    let plan_id = plan_id_of(&base_revision, &result_revision);
    Ok(Plan {
        plan_id,
        base_revision,
        result_revision,
        diff,
        references,
    })
}

/// Compute a promotion [`Plan`] for a source snapshot against a live TARGET
/// environment (issue #44): the database-backed dry run.
///
/// Exports the target's current promotable configuration (through the scope-forced
/// repositories, so the read is confined to exactly the target `(tenant,
/// environment)`), then evaluates the plan with each source reference checked for
/// existence in the target via [`crate::esv::reference_resolves`] (a presence check
/// that opens no secret value). The outer `Result` carries a persistence fault; the
/// inner `Result` carries the plan or the per-item [`PlanError`]s (unresolved
/// references). This mutates nothing: it is a pure dry run.
///
/// # Errors
///
/// [`StoreError`] on a persistence fault while exporting the target or resolving a
/// reference.
pub async fn plan_promotion(
    target: &crate::repository::ScopedStore<'_>,
    source: &Snapshot,
) -> Result<Result<Plan, Vec<PlanError>>, StoreError> {
    let target_snapshot = crate::snapshot::export(target).await?;
    let references = collect_references(source);
    let mut resolved: std::collections::HashSet<String> = std::collections::HashSet::new();
    for reference in &references {
        // A variable a promotion CREATES satisfies its own references: a reference
        // resolves if the target already carries it OR the source promotes a
        // variable of that name. Secret references must pre-exist in the target (a
        // secret value never travels).
        let promoted_here = matches!(reference.kind, crate::esv::ReferenceKind::Variable)
            && source
                .resources
                .variable
                .iter()
                .any(|variable| variable.name == reference.name);
        if promoted_here || crate::esv::reference_resolves(target, reference).await? {
            resolved.insert(reference.render());
        }
    }
    Ok(evaluate_plan(source, &target_snapshot, |reference| {
        resolved.contains(&reference.render())
    }))
}

/// The deterministic plan id: a hash of the base and result revisions.
fn plan_id_of(base_revision: &str, result_revision: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base_revision.as_bytes());
    hasher.update(b"\n");
    hasher.update(result_revision.as_bytes());
    format!("plan_{}", hex_lower(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{
        ChangeKind, PROMOTED_RESOURCE_TYPES, PlanError, PromotedResourceType, collect_references,
        diff, evaluate_plan, revision,
    };
    use crate::classification::{ResourceClassification, ResourceType, classify};
    use crate::esv::{Reference, ReferenceKind};
    use crate::snapshot::{
        BrandAssetMetaSnapshot, BrandSnapshot, ClientSnapshot, ConnectorSnapshot,
        DcrPolicySnapshot, FlowVersionSnapshot, LocaleBundleSnapshot, MessageTemplateSnapshot,
        OrgConnectionSnapshot, ResourceServerSnapshot, RoutingRuleSnapshot,
        SNAPSHOT_RESOURCE_TYPES, SNAPSHOT_SCHEMA_VERSION, SignupFormSnapshot, Snapshot,
        SnapshotResources, UpstreamTokenGrantSnapshot, VariableSnapshot,
    };

    fn snapshot(resources: SnapshotResources) -> Snapshot {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
            resources,
        }
    }

    fn variable(name: &str, value: &str) -> VariableSnapshot {
        VariableSnapshot {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    fn resource_server(audience: &str, token_format: &str) -> ResourceServerSnapshot {
        ResourceServerSnapshot {
            audience: audience.to_owned(),
            token_format: token_format.to_owned(),
            access_token_ttl_secs: None,
            permission_claims_enabled: false,
        }
    }

    /// The same fixture with the issue #98 opt-in ON, so a diff can be driven by
    /// THAT field alone rather than by the format.
    fn resource_server_opted_in(audience: &str, token_format: &str) -> ResourceServerSnapshot {
        ResourceServerSnapshot {
            permission_claims_enabled: true,
            ..resource_server(audience, token_format)
        }
    }

    /// The permission-claim opt-in is a PROMOTABLE difference on its own.
    ///
    /// The diff keys resource servers by `audience` and compares the whole serialized
    /// element, so a field that reaches `ResourceServerSnapshot` is compared for free.
    /// What this test guards is that "for free" holds at all: a field the diff never
    /// looks at is a field a promotion silently drops, and only a case driven by THIS
    /// field alone can tell the two apart.
    ///
    /// What it does NOT guard, stated because the obvious guess is wrong: it is not a
    /// tripwire on `skip_serializing_if`. Measured by adding `#[serde(default,
    /// skip_serializing_if = "std::ops::Not::not")]` to the field, which leaves this
    /// test and all of `tests/config_promotion.rs` green, because the opted-out side
    /// then omits the key while the opted-in side still carries it, so the two
    /// elements still do not serialize identically and the diff still fires. The
    /// property that change WOULD break is byte-stability of the export, which
    /// `the_permission_claim_opt_in_is_always_serialized_in_both_directions` in
    /// `crate::snapshot` asserts.
    #[test]
    fn the_permission_claim_opt_in_alone_is_an_update() {
        let source = snapshot(SnapshotResources {
            resource_server: vec![resource_server_opted_in("https://api.test", "at_jwt")],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            resource_server: vec![resource_server("https://api.test", "at_jwt")],
            ..SnapshotResources::default()
        });
        let diff = diff(&source, &target);
        let changes: Vec<_> = diff
            .changes
            .iter()
            .filter(|change| change.resource_type == ResourceType::ResourceServer)
            .collect();
        assert_eq!(changes.len(), 1, "one resource-server change: {changes:?}");
        assert_eq!(changes[0].kind, ChangeKind::Update);
        assert_eq!(changes[0].key, "https://api.test");
    }

    fn dcr_policy(name: &str, primitives: serde_json::Value) -> DcrPolicySnapshot {
        DcrPolicySnapshot {
            name: name.to_owned(),
            primitives,
        }
    }

    fn flow_version(
        journey_id: &str,
        version: i32,
        step: &str,
        pinned: bool,
    ) -> FlowVersionSnapshot {
        FlowVersionSnapshot {
            journey_id: journey_id.to_owned(),
            version,
            artifact: serde_json::json!({ "entry": step }),
            pinned,
        }
    }

    #[test]
    fn flow_version_diff_is_additive_and_pin_independent() {
        // The source carries v1 and v2 of a journey (v2 pinned); the target already has v1
        // (same artifact) plus its OWN local v9. The diff must import ONLY the missing v2,
        // leave the target's v9 alone (never a delete), and ignore the pin difference.
        let source = snapshot(SnapshotResources {
            flow_version: vec![
                flow_version("login", 1, "a", false),
                flow_version("login", 2, "b", true),
            ],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            flow_version: vec![
                flow_version("login", 1, "a", true),
                flow_version("login", 9, "z", false),
            ],
            ..SnapshotResources::default()
        });
        let changes = diff(&source, &target);
        assert_eq!(changes.len(), 1, "only the missing version is a change");
        assert_eq!(
            changes.changes()[0].resource_type,
            ResourceType::FlowVersion
        );
        assert_eq!(changes.changes()[0].key, "login@2");
        assert_eq!(changes.changes()[0].kind, ChangeKind::Create);
    }

    #[test]
    fn flow_version_diff_flags_a_differing_artifact_as_an_update_conflict() {
        // The same (journey_id, version) with a DIFFERENT artifact is an append-only conflict,
        // surfaced as an Update the apply refuses (never an overwrite).
        let source = snapshot(SnapshotResources {
            flow_version: vec![flow_version("login", 1, "source", false)],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            flow_version: vec![flow_version("login", 1, "target", false)],
            ..SnapshotResources::default()
        });
        let changes = diff(&source, &target);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes.changes()[0].kind, ChangeKind::Update);
        assert_eq!(changes.changes()[0].key, "login@1");
    }

    #[test]
    fn revision_ignores_the_flow_version_pin_but_tracks_the_artifact() {
        // Two snapshots with the SAME versions but a different active pin hash to the SAME
        // revision: the pin is not part of the promotable configuration (the activation gate).
        let pinned_v1 = snapshot(SnapshotResources {
            flow_version: vec![
                flow_version("login", 1, "a", true),
                flow_version("login", 2, "b", false),
            ],
            ..SnapshotResources::default()
        });
        let pinned_v2 = snapshot(SnapshotResources {
            flow_version: vec![
                flow_version("login", 1, "a", false),
                flow_version("login", 2, "b", true),
            ],
            ..SnapshotResources::default()
        });
        assert_eq!(
            revision(&pinned_v1).expect("rev"),
            revision(&pinned_v2).expect("rev"),
            "the active pin must not perturb the promotable revision"
        );
        // A differing artifact DOES change the revision.
        let changed = snapshot(SnapshotResources {
            flow_version: vec![
                flow_version("login", 1, "a", true),
                flow_version("login", 2, "CHANGED", false),
            ],
            ..SnapshotResources::default()
        });
        assert_ne!(
            revision(&pinned_v1).expect("rev"),
            revision(&changed).expect("rev")
        );
    }

    #[test]
    fn message_template_key_round_trips_when_either_half_holds_the_separator() {
        // The ordinary case reads as the operator wrote it.
        assert_eq!(
            super::message_template_key("email_otp", "en-us"),
            "email_otp/en-us"
        );
        assert_eq!(
            super::split_message_template_key("email_otp/en-us"),
            Some(("email_otp".to_owned(), "en-us".to_owned()))
        );
        // Neither half is character-constrained: `Locale::new` normalizes a tag but does not
        // restrict it, and `message_templates.kind` carries no CHECK. A raw join would make
        // these two DIFFERENT templates collide on one key, and the diff would treat one as
        // an update of the other.
        let left = super::message_template_key("a/b", "c");
        let right = super::message_template_key("a", "b/c");
        assert_ne!(left, right, "a raw join would make these the same key");
        assert_eq!(
            super::split_message_template_key(&left),
            Some(("a/b".to_owned(), "c".to_owned()))
        );
        assert_eq!(
            super::split_message_template_key(&right),
            Some(("a".to_owned(), "b/c".to_owned()))
        );
        // A literal backslash survives, including one immediately before the separator.
        let backslash = super::message_template_key("a\\", "b");
        assert_eq!(
            super::split_message_template_key(&backslash),
            Some(("a\\".to_owned(), "b".to_owned())),
            "a trailing backslash must not escape the separator itself"
        );
        // A key with no unescaped separator is not one of ours.
        assert_eq!(super::split_message_template_key("no-separator"), None);
    }

    #[test]
    fn flow_version_key_round_trips_even_with_an_at_in_the_journey_id() {
        assert_eq!(super::flow_version_key("login", 3), "login@3");
        assert_eq!(
            super::parse_flow_version_key("login@3"),
            Some(("login".to_owned(), 3))
        );
        // A journey id carrying '@' still round-trips (the version is the numeric tail).
        assert_eq!(
            super::parse_flow_version_key("weird@id@12"),
            Some(("weird@id".to_owned(), 12))
        );
        assert_eq!(super::parse_flow_version_key("no-version"), None);
    }

    #[test]
    fn promoted_types_are_all_promotable_and_scope_independent() {
        // Every promoted type is classified promotable (never runtime or
        // environment-identity), so the engine can never move identity.
        for resource in PROMOTED_RESOURCE_TYPES {
            assert_eq!(
                classify(resource),
                ResourceClassification::Promotable,
                "{} must be promotable",
                resource.as_str()
            );
        }
        // The client type is deliberately NOT promoted (scope-embedded identity).
        assert!(!PROMOTED_RESOURCE_TYPES.contains(&ResourceType::Client));
    }

    // =======================================================================
    // The drift lock (issue #475).
    //
    // Three things must agree and, before this, nothing forced them to: the
    // PROMOTED_RESOURCE_TYPES list, the `promoted_projection` that decides what a
    // revision and a diff actually see, and the repository's transactional apply
    // dispatch. All three had silently diverged, which is exactly why a promotion
    // carried no branding, locales or signup fields while the export did.
    //
    // The dispatch agreement is locked at COMPILE time (the apply matches
    // exhaustively on the generated `PromotedResourceType`, so a new entry in the
    // macro list breaks the build until its arm exists). The two below are measured
    // here, and deliberately measured WITHOUT restating the answer: the projection
    // test reads the SERIALIZED projection keyed by `ResourceType::as_str`, so it
    // holds no second copy of "which types are promoted" and no self-compared count.
    // =======================================================================

    /// One snapshot with EVERY snapshot resource type populated, for the projection
    /// witness. Deliberately not `Default`-based: the point is that no array is empty,
    /// so an array the projection empties is distinguishable from one it carries.
    fn fully_populated_snapshot() -> Snapshot {
        snapshot(SnapshotResources {
            client: vec![ClientSnapshot {
                client_id: "cli_source".to_owned(),
                display_name: "App".to_owned(),
                token_endpoint_auth_method: "none".to_owned(),
                redirect_uris: vec!["https://app.test/cb".to_owned()],
                post_logout_redirect_uris: Vec::new(),
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                consent_mode: "explicit".to_owned(),
                skip_consent: false,
                store_skipped_consent: false,
                require_pushed_authorization_requests: false,
                require_auth_time: false,
                jwks: None,
                jwks_uri: None,
                token_endpoint_auth_signing_alg: None,
                refresh_rotation: None,
                secret: None,
            }],
            resource_server: vec![resource_server("https://api.test", "at_jwt")],
            dcr_policy: vec![DcrPolicySnapshot {
                name: "open".to_owned(),
                primitives: serde_json::json!([]),
            }],
            variable: vec![variable("flag", "on")],
            connector: vec![ConnectorSnapshot {
                connector_slug: "okta".to_owned(),
                definition: serde_json::json!({"issuer": "https://idp.test"}),
                enabled: true,
                secret: None,
            }],
            org_connection: vec![OrgConnectionSnapshot {
                organization_id: "org_a".to_owned(),
                connector_id: "con_a".to_owned(),
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            }],
            routing_rule: vec![RoutingRuleSnapshot {
                rule_kind: "domain".to_owned(),
                domain: Some("acme.test".to_owned()),
                client_id: None,
                user_bidx: None,
                org_connection_id: "ocn_a".to_owned(),
                priority: 1,
                enabled: true,
            }],
            upstream_token_grant: vec![UpstreamTokenGrantSnapshot {
                client_id: "cli_source".to_owned(),
                org_connection_id: "ocn_a".to_owned(),
                enabled: true,
            }],
            brand: vec![brand_fixture("acme")],
            locale_bundle: vec![LocaleBundleSnapshot {
                locale: "fr".to_owned(),
                is_env_default: true,
                entries: serde_json::json!({"1": "Bonjour"}),
            }],
            signup_form: vec![SignupFormSnapshot {
                client_id: "cli_source".to_owned(),
                fields: serde_json::json!([]),
            }],
            flow_version: vec![FlowVersionSnapshot {
                journey_id: "login".to_owned(),
                version: 1,
                artifact: serde_json::json!({"id": "login_v1"}),
                pinned: true,
            }],
            message_template: vec![MessageTemplateSnapshot {
                kind: "email_otp".to_owned(),
                locale: "en".to_owned(),
                subject: "Your code".to_owned(),
                body_text: "Code: {{ code }}".to_owned(),
                body_html: Some("<p>Code: {{ code }}</p>".to_owned()),
                locked: false,
            }],
        })
    }

    /// A brand fixture with every optional field filled, so a projection that drops one
    /// is measurable.
    fn brand_fixture(slug: &str) -> BrandSnapshot {
        BrandSnapshot {
            slug: slug.to_owned(),
            is_default: true,
            product_name: "Acme".to_owned(),
            show_wordmark: true,
            brand_token: Some("beta".to_owned()),
            tokens: serde_json::json!({"color_bg": "#ffffff"}),
            tokens_dark: Some(serde_json::json!({"color_bg": "#000000"})),
            slots: serde_json::json!({"footer_legal": "<b>hi</b>"}),
            host_pattern: Some("login.acme.test".to_owned()),
            client_id: Some("cli_source".to_owned()),
            assets: vec![BrandAssetMetaSnapshot {
                kind: "logo".to_owned(),
                content_type: "image/png".to_owned(),
                sha256: "aa".repeat(32),
                size_bytes: 12,
            }],
        }
    }

    /// The per-type resource arrays of a snapshot, keyed by the resource type's WIRE
    /// name. Read out of the SERIALIZED document rather than by naming each field, so
    /// this witness holds no hand-written list of resource types at all: a type the
    /// snapshot gains appears here for free, and one it loses disappears.
    fn resource_arrays(snapshot: &Snapshot) -> serde_json::Map<String, serde_json::Value> {
        let value = serde_json::to_value(snapshot).expect("snapshot serializes");
        value
            .get("resources")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .expect("a snapshot serializes its resources as an object")
    }

    /// EVERY snapshot resource type is populated in the fixture, so the projection
    /// witness below can tell "the projection emptied it" from "it was never there".
    ///
    /// This is the guard that keeps the witness honest as the snapshot grows: a newly
    /// added snapshot resource type with no fixture fails HERE, before it can quietly
    /// pass the projection check by being empty on both sides.
    #[test]
    fn the_projection_witness_fixture_populates_every_snapshot_resource_type() {
        let arrays = resource_arrays(&fully_populated_snapshot());
        assert_eq!(
            arrays.len(),
            SNAPSHOT_RESOURCE_TYPES.len(),
            "the serialized resources object must carry exactly one array per snapshot \
             resource type: {:?}",
            arrays.keys().collect::<Vec<_>>()
        );
        for resource in SNAPSHOT_RESOURCE_TYPES {
            let array = arrays
                .get(resource.as_str())
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| {
                    panic!(
                        "the fixture has no `{}` array; add one so the projection witness \
                         can measure it",
                        resource.as_str()
                    )
                });
            assert!(
                !array.is_empty(),
                "the fixture must populate `{}` for the projection witness to be \
                 non-vacuous",
                resource.as_str()
            );
        }
    }

    /// THE DRIFT LOCK: `promoted_projection` carries exactly the types
    /// `PROMOTED_RESOURCE_TYPES` names, and empties every other snapshot type.
    ///
    /// Both directions fail loudly. A type added to the constant whose projection is
    /// still `Vec::new()` (the exact defect issue #475 records for `brand`,
    /// `locale_bundle` and `signup_form`) fails the "must carry" half, because the
    /// revision and the diff read the projection and would see nothing. A type the
    /// projection carries that the constant does not name fails the "must empty" half,
    /// because the target read would then have to carry it too or every promotion would
    /// look like a permanent drift.
    ///
    /// The witness never restates which types are promoted: the expectation comes from
    /// `PROMOTED_RESOURCE_TYPES` itself, and the observation comes from the serialized
    /// projection keyed by `ResourceType::as_str`.
    #[test]
    fn the_promoted_projection_carries_exactly_the_promoted_types() {
        let full = fully_populated_snapshot();
        let projected = resource_arrays(&super::promoted_projection(&full));
        for resource in SNAPSHOT_RESOURCE_TYPES {
            let promoted = PROMOTED_RESOURCE_TYPES.contains(&resource);
            let array = projected
                .get(resource.as_str())
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| {
                    panic!("the projection dropped the `{}` key", resource.as_str())
                });
            assert_eq!(
                !array.is_empty(),
                promoted,
                "`{}` is {} PROMOTED_RESOURCE_TYPES, so the promoted projection must {} it; \
                 the projection is the only thing `revision` and `diff` read, so a type in \
                 the list with an empty projection promotes nothing",
                resource.as_str(),
                if promoted { "in" } else { "absent from" },
                if promoted { "carry" } else { "empty" }
            );
        }
    }

    /// THE DRIFT LOCK, second half: the promoted set is a strict SUBSET of the
    /// snapshot set.
    ///
    /// A type the engine applies but the snapshot does not export could never reach an
    /// apply (the source document has nowhere to carry it) and would make every target
    /// read look like drift. This also keeps the constant's own doc sentence honest: it
    /// claims a subset relation, and this measures it.
    #[test]
    fn the_promoted_types_are_a_subset_of_the_snapshot_types() {
        for resource in PROMOTED_RESOURCE_TYPES {
            assert!(
                SNAPSHOT_RESOURCE_TYPES.contains(&resource),
                "`{}` is promoted but is not carried in the snapshot export, so a source \
                 document could never carry it",
                resource.as_str()
            );
        }
        assert!(
            PROMOTED_RESOURCE_TYPES.len() < SNAPSHOT_RESOURCE_TYPES.len(),
            "the promoted set is a STRICT subset today (client, signup_form, connector, \
             org_connection, routing_rule and upstream_token_grant are exported but not \
             applied); if that stops being true, the constant's doc must stop saying it"
        );
    }

    /// THE DRIFT LOCK, third half: the narrowing the apply dispatch runs on agrees with
    /// the constant in BOTH directions.
    ///
    /// The dispatch itself is locked at compile time (it matches exhaustively on
    /// `PromotedResourceType`), but that only proves every ENUM variant has an arm. This
    /// proves the enum and the array are the same set, so the compile-time lock is
    /// pointed at the right set: every promoted type narrows, every non-promoted type
    /// does not, and the round trip is the identity.
    #[test]
    fn the_apply_dispatch_narrowing_matches_the_promoted_constant() {
        for resource in ResourceType::ALL {
            let narrowed = PromotedResourceType::from_resource_type(resource);
            assert_eq!(
                narrowed.is_some(),
                PROMOTED_RESOURCE_TYPES.contains(&resource),
                "`{}` narrows to a dispatchable type iff it is promoted; a type that \
                 narrows without being promoted would be applied by a plan that never \
                 enumerates it, and one that is promoted without narrowing would be \
                 refused as a not-found at apply time",
                resource.as_str()
            );
            if let Some(narrowed) = narrowed {
                assert_eq!(narrowed.as_resource_type(), resource);
            }
        }
    }

    /// The per-CLIENT brand selection key is normalized OUT of the promoted projection,
    /// asserted as BEHAVIOUR: two brands identical but for `client_id` promote as the
    /// same revision and produce no diff.
    ///
    /// This is the brand analogue of the custom-journey activation gate. A `client_id`
    /// is a scope-embedded id, so carrying it would overwrite the target admin's own
    /// per-client brand selection with a value that can never match there.
    #[test]
    fn the_brand_per_client_selection_key_never_enters_the_revision_or_the_diff() {
        let with_key = snapshot(SnapshotResources {
            brand: vec![brand_fixture("acme")],
            ..SnapshotResources::default()
        });
        let without_key = snapshot(SnapshotResources {
            brand: vec![BrandSnapshot {
                client_id: None,
                ..brand_fixture("acme")
            }],
            ..SnapshotResources::default()
        });
        let other_key = snapshot(SnapshotResources {
            brand: vec![BrandSnapshot {
                client_id: Some("cli_target".to_owned()),
                ..brand_fixture("acme")
            }],
            ..SnapshotResources::default()
        });
        assert_eq!(
            revision(&with_key).expect("rev"),
            revision(&without_key).expect("rev"),
            "the per-client selection key must not perturb the promotable revision"
        );
        assert_eq!(
            revision(&with_key).expect("rev"),
            revision(&other_key).expect("rev"),
            "a DIFFERENT per-client key must not perturb it either"
        );
        assert!(
            diff(&with_key, &other_key).is_empty(),
            "a promotion must not carry the per-client selection key into the diff"
        );

        // The control: a field that IS promotable definition still moves both.
        let renamed = snapshot(SnapshotResources {
            brand: vec![BrandSnapshot {
                product_name: "Globex".to_owned(),
                ..brand_fixture("acme")
            }],
            ..SnapshotResources::default()
        });
        assert_ne!(
            revision(&with_key).expect("rev"),
            revision(&renamed).expect("rev")
        );
        assert_eq!(diff(&with_key, &renamed).len(), 1);
    }

    /// A brand's per-DOMAIN key and its asset METADATA are promotable definition and DO
    /// enter the revision and the diff (the counterpart to the test above): a promotion
    /// that dropped them would silently leave the target's per-host selection and its
    /// logo binding behind.
    #[test]
    fn the_brand_host_key_and_asset_metadata_are_promotable_definition() {
        let base = snapshot(SnapshotResources {
            brand: vec![brand_fixture("acme")],
            ..SnapshotResources::default()
        });
        let rehosted = snapshot(SnapshotResources {
            brand: vec![BrandSnapshot {
                host_pattern: Some("id.acme.test".to_owned()),
                ..brand_fixture("acme")
            }],
            ..SnapshotResources::default()
        });
        assert_ne!(
            revision(&base).expect("rev"),
            revision(&rehosted).expect("rev")
        );
        assert_eq!(diff(&base, &rehosted).len(), 1);

        let relogoed = snapshot(SnapshotResources {
            brand: vec![BrandSnapshot {
                assets: vec![BrandAssetMetaSnapshot {
                    sha256: "bb".repeat(32),
                    ..brand_fixture("acme").assets.remove(0)
                }],
                ..brand_fixture("acme")
            }],
            ..SnapshotResources::default()
        });
        assert_ne!(
            revision(&base).expect("rev"),
            revision(&relogoed).expect("rev"),
            "a changed logo digest is a promotable change the diff must show"
        );
        assert_eq!(diff(&base, &relogoed).len(), 1);
    }

    /// A locale bundle promotes WHOLE: the tag, the env-default flag, and the entries
    /// map each move the revision and the diff, so nothing about a bundle is silently
    /// per-environment.
    #[test]
    fn every_locale_bundle_field_is_promotable_definition() {
        let bundle = |is_env_default: bool, greeting: &str| {
            snapshot(SnapshotResources {
                locale_bundle: vec![LocaleBundleSnapshot {
                    locale: "fr".to_owned(),
                    is_env_default,
                    entries: serde_json::json!({ "1": greeting }),
                }],
                ..SnapshotResources::default()
            })
        };
        let base = bundle(true, "Bonjour");
        assert_ne!(
            revision(&base).expect("rev"),
            revision(&bundle(false, "Bonjour")).expect("rev"),
            "the env-default flag is promotable definition"
        );
        assert_ne!(
            revision(&base).expect("rev"),
            revision(&bundle(true, "Salut")).expect("rev"),
            "an entry string is promotable definition"
        );
        assert_eq!(diff(&base, &bundle(false, "Salut")).len(), 1);
        // A different TAG is a different resource, not an update of this one.
        let other_tag = snapshot(SnapshotResources {
            locale_bundle: vec![LocaleBundleSnapshot {
                locale: "de".to_owned(),
                is_env_default: true,
                entries: serde_json::json!({"1": "Bonjour"}),
            }],
            ..SnapshotResources::default()
        });
        let changes = diff(&base, &other_tag);
        assert_eq!(changes.len(), 2, "one create and one delete: {changes:?}");
    }

    #[test]
    fn diff_detects_create_update_and_delete() {
        let source = snapshot(SnapshotResources {
            variable: vec![variable("a", "1"), variable("b", "source")],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            variable: vec![variable("b", "target"), variable("c", "gone")],
            ..SnapshotResources::default()
        });
        let changes = diff(&source, &target);
        assert_eq!(changes.len(), 3);
        // Ordered by natural key: a (create), b (update), c (delete).
        assert_eq!(changes.changes()[0].key, "a");
        assert_eq!(changes.changes()[0].kind, ChangeKind::Create);
        assert_eq!(changes.changes()[1].key, "b");
        assert_eq!(changes.changes()[1].kind, ChangeKind::Update);
        assert_eq!(changes.changes()[2].key, "c");
        assert_eq!(changes.changes()[2].kind, ChangeKind::Delete);
    }

    #[test]
    fn diff_is_empty_for_identical_promotable_config() {
        let resources = SnapshotResources {
            resource_server: vec![resource_server("https://api", "at_jwt")],
            dcr_policy: vec![dcr_policy("open", serde_json::json!([]))],
            variable: vec![variable("k", "v")],
            ..SnapshotResources::default()
        };
        let a = snapshot(resources.clone());
        let b = snapshot(resources);
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn diff_ignores_clients_entirely() {
        use crate::snapshot::ClientSnapshot;
        let with_client = |client_id: &str| {
            snapshot(SnapshotResources {
                client: vec![ClientSnapshot {
                    client_id: client_id.to_owned(),
                    display_name: "app".to_owned(),
                    token_endpoint_auth_method: "none".to_owned(),
                    redirect_uris: vec![],
                    post_logout_redirect_uris: vec![],
                    frontchannel_logout_uri: None,
                    frontchannel_logout_session_required: false,
                    consent_mode: "explicit".to_owned(),
                    skip_consent: false,
                    store_skipped_consent: false,
                    require_pushed_authorization_requests: false,
                    require_auth_time: false,
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    refresh_rotation: None,
                    secret: None,
                }],
                ..SnapshotResources::default()
            })
        };
        // Two environments with DIFFERENT client ids still produce an empty diff:
        // clients are not promoted, so their divergence is invisible to the engine.
        assert!(diff(&with_client("cli_source"), &with_client("cli_target")).is_empty());
    }

    #[test]
    fn revision_ignores_clients_but_tracks_promoted_config() {
        use crate::snapshot::ClientSnapshot;
        let client = ClientSnapshot {
            client_id: "cli_x".to_owned(),
            display_name: "app".to_owned(),
            token_endpoint_auth_method: "none".to_owned(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            consent_mode: "explicit".to_owned(),
            skip_consent: false,
            store_skipped_consent: false,
            require_pushed_authorization_requests: false,
            require_auth_time: false,
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            refresh_rotation: None,
            secret: None,
        };
        let base = snapshot(SnapshotResources {
            variable: vec![variable("k", "v")],
            ..SnapshotResources::default()
        });
        let with_client = snapshot(SnapshotResources {
            client: vec![client],
            variable: vec![variable("k", "v")],
            ..SnapshotResources::default()
        });
        // A differing client does NOT change the revision.
        assert_eq!(
            revision(&base).expect("rev"),
            revision(&with_client).expect("rev")
        );
        // A differing promoted variable DOES.
        let changed = snapshot(SnapshotResources {
            variable: vec![variable("k", "w")],
            ..SnapshotResources::default()
        });
        assert_ne!(
            revision(&base).expect("rev"),
            revision(&changed).expect("rev")
        );
    }

    #[test]
    fn collect_references_finds_var_and_secret_tokens() {
        let source = snapshot(SnapshotResources {
            variable: vec![
                variable("endpoint", "${var:base_url}"),
                variable("key", "${secret:api_key}"),
                variable("literal", "not a reference"),
            ],
            ..SnapshotResources::default()
        });
        let references = collect_references(&source);
        assert_eq!(references.len(), 2);
        assert!(
            references
                .iter()
                .any(|r| r.kind == ReferenceKind::Variable && r.name == "base_url")
        );
        assert!(
            references
                .iter()
                .any(|r| r.kind == ReferenceKind::Secret && r.name == "api_key")
        );
    }

    #[test]
    fn plan_fails_closed_on_an_unresolved_reference() {
        let source = snapshot(SnapshotResources {
            variable: vec![variable("key", "${secret:missing}")],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources::default());
        // Nothing resolves in the target.
        let errors = evaluate_plan(&source, &target, |_| false).expect_err("must fail closed");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0],
            PlanError::UnresolvedReference(Reference {
                kind: ReferenceKind::Secret,
                name: "missing".to_owned(),
            })
        );
    }

    #[test]
    fn plan_succeeds_when_every_reference_resolves() {
        let source = snapshot(SnapshotResources {
            variable: vec![variable("key", "${secret:present}")],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources::default());
        let plan = evaluate_plan(&source, &target, |_| true).expect("plan builds");
        assert_eq!(plan.diff().len(), 1);
        assert_eq!(plan.references().len(), 1);
        assert!(plan.plan_id().starts_with("plan_"));
        // base != result because the target is empty and the source has a variable.
        assert_ne!(plan.base_revision(), plan.result_revision());
    }

    #[test]
    fn plan_id_and_revisions_are_deterministic() {
        let source = snapshot(SnapshotResources {
            variable: vec![variable("k", "v")],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources::default());
        let a = evaluate_plan(&source, &target, |_| true).expect("a");
        let b = evaluate_plan(&source, &target, |_| true).expect("b");
        assert_eq!(a.plan_id(), b.plan_id());
        assert_eq!(a.base_revision(), b.base_revision());
        assert_eq!(a.result_revision(), b.result_revision());
    }

    #[test]
    fn a_no_op_plan_has_matching_base_and_result_revisions() {
        // When the source already matches the target, base == result: apply is a
        // no-op and re-applying is idempotent.
        let resources = SnapshotResources {
            variable: vec![variable("k", "v")],
            ..SnapshotResources::default()
        };
        let source = snapshot(resources.clone());
        let target = snapshot(resources);
        let plan = evaluate_plan(&source, &target, |_| true).expect("plan");
        assert!(plan.diff().is_empty());
        assert_eq!(plan.base_revision(), plan.result_revision());
    }

    /// A brand with its assets listed in a different DOCUMENT ORDER is the SAME promotable
    /// brand.
    ///
    /// The diff compares the whole serialized brand element, and the target read orders a
    /// brand's assets by kind, so without the projection's own sort a hand authored document
    /// listing `[logo, favicon]` produced an Update on every plan and the promotion never
    /// reached `PromotionOutcome::NoOp`. Driven by the ORDER alone: both sides carry the same
    /// two assets, so only the ordering can make this fail.
    #[test]
    fn a_brands_asset_document_order_is_not_a_promotable_difference() {
        fn asset(kind: &str, marker: &str) -> BrandAssetMetaSnapshot {
            BrandAssetMetaSnapshot {
                kind: kind.to_owned(),
                content_type: "image/png".to_owned(),
                sha256: marker.repeat(64),
                size_bytes: 9,
            }
        }
        let mut authored = brand_fixture("acme");
        authored.assets = vec![asset("logo", "a"), asset("favicon", "b")];
        let mut read_back = brand_fixture("acme");
        read_back.assets = vec![asset("favicon", "b"), asset("logo", "a")];

        let source = snapshot(SnapshotResources {
            brand: vec![authored],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            brand: vec![read_back],
            ..SnapshotResources::default()
        });
        assert!(
            diff(&source, &target).is_empty(),
            "asset document order must not be a change: {:?}",
            diff(&source, &target).changes()
        );
        assert_eq!(
            revision(&source).expect("rev"),
            revision(&target).expect("rev"),
            "asset document order must not perturb the promotable revision"
        );
    }

    /// A brand's `host_pattern` is CANONICALIZED before it is diffed, hashed, or applied.
    ///
    /// Two spellings of one hostname are one host claim. The store column carries the folded
    /// form (the management writer folds at ingest) and the selection matcher folds the
    /// request Host, so a promotion that carried a raw spelling would store a second row the
    /// per-scope unique index cannot see is a duplicate, and both brands would then resolve
    /// for the same request. Measured on the projection's own output as well as through the
    /// diff, because "the two agree" would also hold if BOTH sides kept the raw form.
    #[test]
    fn a_brand_host_pattern_is_canonicalized_before_it_is_diffed() {
        let mut authored = brand_fixture("acme");
        authored.host_pattern = Some("  LOGIN.Acme.Test:8443 ".to_owned());
        let mut stored = brand_fixture("acme");
        stored.host_pattern = Some("login.acme.test".to_owned());

        assert_eq!(
            super::promoted_brand(&authored).host_pattern.as_deref(),
            Some("login.acme.test"),
            "the projection carries the canonical host key, not the authored spelling"
        );

        let source = snapshot(SnapshotResources {
            brand: vec![authored],
            ..SnapshotResources::default()
        });
        let target = snapshot(SnapshotResources {
            brand: vec![stored],
            ..SnapshotResources::default()
        });
        assert!(
            diff(&source, &target).is_empty(),
            "two spellings of one host are one claim: {:?}",
            diff(&source, &target).changes()
        );
        assert_eq!(
            revision(&source).expect("rev"),
            revision(&target).expect("rev")
        );

        // An empty pattern claims no host at all, rather than claiming the empty string.
        let mut blank = brand_fixture("acme");
        blank.host_pattern = Some("   ".to_owned());
        assert_eq!(super::promoted_brand(&blank).host_pattern, None);
    }
}
