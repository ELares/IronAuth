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
//! `name`), and environment variables (keyed by `name`). See
//! [`PROMOTED_RESOURCE_TYPES`]. Environment-IDENTITY (the environment itself, its
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

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::classification::ResourceType;
use crate::error::StoreError;
use crate::esv::Reference;
use crate::snapshot::{Snapshot, SnapshotResources};

/// The promotable resource types this engine diffs, plans, and applies.
///
/// Each has a SCOPE-INDEPENDENT natural key (an `audience` or a `name`, never a
/// scope-embedded identifier) and carries its full promotable state in the
/// snapshot, so it round-trips across environments: applying a source then
/// re-diffing the source against the target yields an empty diff. This is a SUBSET
/// of [`crate::snapshot::SNAPSHOT_RESOURCE_TYPES`] (which additionally carries
/// `client`, excluded here per the module docs).
pub const PROMOTED_RESOURCE_TYPES: [ResourceType; 3] = [
    ResourceType::ResourceServer,
    ResourceType::DcrPolicy,
    ResourceType::Variable,
];

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
#[must_use]
pub fn diff(source: &Snapshot, target: &Snapshot) -> ConfigDiff {
    let mut changes = Vec::new();
    diff_keyed(
        ResourceType::ResourceServer,
        &keyed_resource_servers(&source.resources),
        &keyed_resource_servers(&target.resources),
        &mut changes,
    );
    diff_keyed(
        ResourceType::DcrPolicy,
        &keyed_dcr_policies(&source.resources),
        &keyed_dcr_policies(&target.resources),
        &mut changes,
    );
    diff_keyed(
        ResourceType::Variable,
        &keyed_variables(&source.resources),
        &keyed_variables(&target.resources),
        &mut changes,
    );
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
        ChangeKind, PROMOTED_RESOURCE_TYPES, PlanError, collect_references, diff, evaluate_plan,
        revision,
    };
    use crate::classification::{ResourceClassification, ResourceType, classify};
    use crate::esv::{Reference, ReferenceKind};
    use crate::snapshot::{
        DcrPolicySnapshot, ResourceServerSnapshot, SNAPSHOT_SCHEMA_VERSION, Snapshot,
        SnapshotResources, VariableSnapshot,
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
        }
    }

    fn dcr_policy(name: &str, primitives: serde_json::Value) -> DcrPolicySnapshot {
        DcrPolicySnapshot {
            name: name.to_owned(),
            primitives,
        }
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
}
