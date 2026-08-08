# Org hierarchy inheritance and the `isEntitled` composition

Design record for issue #103, bets 2 and 3. Neither is graduated by this document; #103
says so explicitly, and the point here is to make the later build cheap rather than to
start it.

Every schema claim below is backed by a migration dry-run that runs in CI:
`crates/ironauth-store/tests/hierarchy_entitlement_headroom.rs` applies
`docs/design/candidate-0999-hierarchy-entitlements.sql` to a database carrying the whole
shipped chain. If the chain drifts so that these extensions stop being additive, that test
goes red and this document is retracted by the build rather than by somebody noticing years
later. A schema review whose conclusion nothing re-checks is exactly the kind of claim this
project has been bitten by.

## Bet 2: hierarchy inheritance

### The tree already exists and needs no migration

`organizations.parent_id` was added by migration 0084: nullable, self-referential, and
described there as tree-CAPABLE. Nothing traverses it, which is the deliberate state. So
the hierarchy bet adds no tree; it adds the two things a traversal would need.

### Inheritance is per-field, not per-organization

The tempting model is a boolean: an organization either inherits its parent's policy or it
does not. That is wrong for the case the feature exists to serve. A subsidiary typically
inherits its parent's session lifetime while overriding its MFA requirement, because the
parent sets the commercial default and the subsidiary answers to its own regulator. An
all-or-nothing switch forces that org to re-declare every field it agreed with, and the
re-declared copies then silently stop tracking the parent.

So the candidate models `(organization, policy_field) -> inherit | override`. The cost is
one row per deliberately-diverging field, which is small and, more importantly,
*legible*: an operator can see exactly which fields an organization has taken ownership of.

### Resolution order, and where it plugs in

The existing resolver in `ironauth-store/src/org_policy.rs` already composes
`tenant > environment > organization`. Hierarchy inserts *between* environment and
organization: an organization's effective policy is its own fields where it overrides, and
its nearest ancestor's resolved value where it inherits.

That ordering matters and is not arbitrary. Putting the parent chain *below* the
environment would let a parent organization override an environment-wide security floor,
which is the one thing an environment-level policy exists to prevent.

### Termination

A cycle in the parent chain makes resolution non-terminating. The shipped schema permits
one today, harmlessly, because nothing walks the tree. A runtime must not assume
otherwise: the guard belongs in the write path that sets `parent_id`, and
`hierarchy_depth` in the candidate is the materialised depth that makes both the guard and
a bounded walk cheap.

Recording it here because "the schema allows a cycle" is invisible until the first
traversal ships, and that is the worst moment to discover it.

## Bet 3: entitlements

### The finding: a feature IS a permission

The criterion asks for confirmation that "no schema decision makes features a second
universe". The confirmation is that features need **no new slug table at all**.

`permissions` (migration 0091) already carries a namespaced slug grammar with `.` as the
delimiter, described in that migration as "namespaced BY CONSTRUCTION, not by convention",
with `billing.invoice.read` given as the shape. A feature slug is an ordinary permission
slug, and what distinguishes it is `permissions.kind`.

**Correcting the first version of this section**, which said "a feature slug is a
permission slug in a reserved first segment. That is the whole mechanism." No segment was
reserved. There was no prefix, no CHECK, and nothing that could tell a feature from a
permission, so the sentence named a mechanism that did not exist.

The reserved namespace already ships and it is not a slug prefix. Migration 0091 gives
`permissions.kind` a `CHECK (kind IN ('permission', 'entitlement'))` from day one and keys
its live-unique index on `(tenant_id, environment_id, kind, slug)`, expressly so
`plan.enterprise` can exist as an entitlement while a permission of the same slug exists
independently. 0091 wrote that headroom for this bet; the first draft of the candidate did
not use it.

So bet 3 adds only the bundle: `org_plans`, `org_plan_features`, and
`org_plan_assignments`.

### What keeps the two from drifting

`org_plan_features` carries a **composite** foreign key to `permissions (id, kind)`,
against a `permission_kind` column pinned to `'entitlement'` by its own CHECK. Two things
follow, and both are asserted rather than asserted-about.

A plan cannot grant a feature the vocabulary does not define:
`a_plan_can_only_grant_a_feature_the_permission_vocabulary_defines` inserts an orphan and
requires the database to refuse it.

A plan cannot bundle an ordinary PERMISSION:
`a_plan_can_bundle_an_entitlement_and_never_an_ordinary_permission` seeds one row of each
kind, bundles the entitlement successfully, then tries the permission under every value
`permission_kind` can legally hold and requires both to be refused. A plain
`REFERENCES permissions (id)`, which is what the first draft had, permits it.

That second one is not tidiness. A plan is a **billing** artifact an operator edits to sell
a tier; a permission is a grant of authority. If one can carry the other, adding a plan
means writing an access-control policy without knowing it.

This is the difference between the products that got this right and the ones that did not.
Where features are their own table with their own names, a plan can grant `export_csv`
while the permission model knows only `report.export`, and no single query can answer
whether a caller may act. Here both resolve through one join.

### The `isEntitled` composition

A future check answers one question, "may this subject do this thing", over three inputs:

1. **Permissions** the subject holds through org roles (`org_role_permissions`, migration
   0092), which is the existing RBAC path.
2. **Features** granted by the plan the subject's organization is assigned
   (`org_plan_assignments` to `org_plan_features`).
3. **Plans**, which are only the bundling; they carry no authority of their own.

Because 1 and 2 both terminate in `permissions.id`, the composition is a union over
permission ids, not a reconciliation between two vocabularies. A caller asks once and the
resolver decides whether the grant arrived by role or by plan.

A feature and a permission are interchangeable at the point of the CHECK and distinct at
the point of ADMINISTRATION, and that split is the design rather than an unresolved
tension. The check unions permission ids and does not care how the grant arrived, which is
what makes one query sufficient. Administration cares a great deal: `kind` is what stops a
plan from bundling authority, and `permissions.kind` is immutable by GRANT (0091 never
lists it in an UPDATE column list), so a row cannot be reclassified into the other
category after the fact.

### Not in scope

Billing, subscription state, proration, and any notion of payment. `org_plan_assignments`
records which plan an organization is on and nothing about why or until when. Whatever
drives that column is a separate system, and #103 is explicit that only the entitlement
schema headroom is in scope.

## What a build should not have to rediscover

- The tree exists; do not add another parent column.
- Inheritance is per-field, or subsidiaries silently stop tracking their parent.
- The parent chain resolves between environment and organization, never below environment.
- Cycles are currently possible and must be guarded at the write path.
- Features are permissions. Adding a `features` table is the mistake this bet exists to
  avoid.
