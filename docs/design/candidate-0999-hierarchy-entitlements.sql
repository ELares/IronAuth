-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- CANDIDATE migration, NOT part of the shipped chain (issue #103, criterion 4).
--
-- This file is evidence, not a deliverable. Criterion 4 asks for "a recorded schema
-- review [that] confirms hierarchy and entitlement extensions require no breaking
-- migration, with a migration dry-run as evidence". A review asserting "no breaking
-- migration" without attempting one is a claim about code nobody has written; this is
-- the attempt, and `crates/ironauth-store/tests/hierarchy_entitlement_headroom.rs`
-- applies it to a real database on top of the whole shipped chain.
--
-- It is deliberately NOT in `crates/ironauth-store/migrations/`. Shipping it would
-- graduate bets 2 and 3, which this issue explicitly does not do ("this issue does not
-- graduate any of them to stable"). When they are built, the real migration is expected
-- to look like this, and the test is what keeps that expectation honest as the chain
-- moves underneath it.
--
-- EVERY statement is additive: ADD COLUMN (nullable, no default), CREATE TABLE, CREATE
-- INDEX. Nothing drops, renames, retypes, or backfills. That is what "no breaking
-- migration" has to mean concretely, and it is checkable rather than assertable.

-- ---------------------------------------------------------------- BET 2 -------
-- Hierarchy. `organizations.parent_id` already exists (migration 0084, nullable and
-- self-referential, described there as tree-CAPABLE), so the tree needs NO new column.
-- What a hierarchy runtime would add is the resolved-inheritance cache and the guard
-- that keeps the tree a tree.

-- A cycle in the parent chain would make inheritance resolution non-terminating. The
-- shipped schema permits one today, because nothing walks the tree yet. This is the
-- guard a runtime needs, and it is additive: a CHECK on a new column rather than a
-- constraint on the existing one, so no existing row can violate it.
ALTER TABLE organizations
    ADD COLUMN hierarchy_depth integer;

-- "Which policy fields does a child inherit from its parent" is per-field, not
-- all-or-nothing: a subsidiary may inherit its parent's session TTL while overriding its
-- MFA requirement. A per-(org, field) row expresses that; a boolean on the org does not.
CREATE TABLE org_policy_inheritance (
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    organization_id text        NOT NULL,
    -- The policy field this row governs, as the field name the resolver already knows.
    policy_field    text        NOT NULL,
    -- INHERIT from the parent, or OVERRIDE with this organization's own value.
    mode            text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT org_policy_inheritance_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT org_policy_inheritance_mode_valid
        CHECK (mode IN ('inherit', 'override')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

CREATE UNIQUE INDEX org_policy_inheritance_field_live_uniq
    ON org_policy_inheritance (tenant_id, environment_id, organization_id, policy_field)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------- BET 3 -------
-- Entitlements. The critical finding the review records: features need NO new slug
-- table. `permissions` (migration 0091) already carries a namespaced slug grammar with
-- `.` as the delimiter, described there as "namespaced BY CONSTRUCTION, not by
-- convention". A feature is a permission, which is exactly what keeps features from
-- becoming a second universe.
--
-- CORRECTION to the first draft of this file, which said a feature is "a permission slug
-- in a reserved first segment". Nothing reserved any segment: there was no prefix, no
-- CHECK, and no way for the schema to tell a feature from an ordinary permission. The
-- sentence described a mechanism that did not exist, and the FOREIGN KEY below would have
-- let a plan bundle `billing.invoice.delete` as cheerfully as `plan.seats`.
--
-- The reserved namespace ALREADY SHIPS and it is not a slug prefix. Migration 0091's
-- `permissions.kind` carries `CHECK (kind IN ('permission', 'entitlement'))` from day
-- one, and its live-unique index is keyed on `(tenant_id, environment_id, kind, slug)`
-- precisely so `plan.enterprise` can exist as an entitlement while a permission of the
-- same slug exists independently. 0091 wrote that headroom for this bet and the first
-- draft of this candidate did not use it.
--
-- So bet 3 adds only the BUNDLE: a plan, and which ENTITLEMENT slugs it grants.

-- Required by Postgres for the composite foreign key below: a REFERENCES clause needs a
-- unique constraint on exactly the referenced column list. `id` is already the primary
-- key, so this adds no new uniqueness and cannot fail on existing data; it exists solely
-- to make `(id, kind)` a legal target. Additive, and it takes no lock beyond the index
-- build.
ALTER TABLE permissions
    ADD CONSTRAINT permissions_id_kind_uniq UNIQUE (id, kind);

CREATE TABLE org_plans (
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The plan's stable name, in the same namespaced grammar permissions use.
    slug            text        NOT NULL,
    display_name    text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT org_plans_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE UNIQUE INDEX org_plans_slug_live_uniq
    ON org_plans (tenant_id, environment_id, slug)
    WHERE deleted_at IS NULL;

-- A plan grants ENTITLEMENT slugs. The composite FOREIGN KEY is the whole point, and it
-- is composite for a reason a plain `REFERENCES permissions (id)` cannot achieve: a plan
-- must be unable to bundle an ordinary PERMISSION.
--
-- `permission_kind` is pinned to `'entitlement'` by its own CHECK and carried into the
-- foreign key, so the referenced row must be an entitlement. There is no value a writer
-- can put in the column that reaches a `kind = 'permission'` row, and the enforcement is
-- structural rather than a rule some later insert path has to remember. Getting this
-- wrong in the other direction is the expensive mistake: a plan that could bundle
-- `billing.invoice.delete` would turn a BILLING artifact into a grant of authority, and
-- an operator adding a plan would be writing an access-control policy without knowing it.
CREATE TABLE org_plan_features (
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    plan_id         text        NOT NULL,
    permission_id   text        NOT NULL,
    -- Constant by construction. A column rather than a literal in the FK because
    -- Postgres has no way to state "reference only rows whose kind is X" without one.
    permission_kind text        NOT NULL DEFAULT 'entitlement',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT org_plan_features_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT org_plan_features_kind_is_entitlement
        CHECK (permission_kind = 'entitlement'),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (plan_id) REFERENCES org_plans (id),
    FOREIGN KEY (permission_id, permission_kind) REFERENCES permissions (id, kind)
);

CREATE UNIQUE INDEX org_plan_features_pair_live_uniq
    ON org_plan_features (tenant_id, environment_id, plan_id, permission_id)
    WHERE deleted_at IS NULL;

-- Which plan an organization is on. Nullable by absence (no row means no plan), so
-- every existing organization is unaffected.
CREATE TABLE org_plan_assignments (
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    organization_id text        NOT NULL,
    plan_id         text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT org_plan_assignments_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (plan_id) REFERENCES org_plans (id)
);

CREATE UNIQUE INDEX org_plan_assignments_org_live_uniq
    ON org_plan_assignments (tenant_id, environment_id, organization_id)
    WHERE deleted_at IS NULL;
