-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The role-to-permission mapping (issue #98, milestone M10).
--
-- Creates `org_role_permissions`: WHICH permissions of an environment's
-- vocabulary one organization's role grants. Migration 0091 shipped the
-- vocabulary (a permission is a NAME and a label); this is the table that gives
-- a permission its authorization meaning, and it is the only place in the model
-- where the two sides meet.
--
-- ---------------------------------------------------------------------------
-- (1) The shape: an ENVIRONMENT-scoped vocabulary joined to an
--     ORGANIZATION-scoped role, so this row carries the organization and the
--     vocabulary does not.
-- ---------------------------------------------------------------------------
-- A reader arriving from 0091 will have just been told that a permission has no
-- `organization_id` and that the isolation policy is that table's COMPLETE
-- fence. Both statements stay true, and neither carries over to this table:
--
--   * `permissions` is per environment because a permission NAMES AN API
--     CAPABILITY, and one string cannot sensibly mean different things to two
--     organizations calling the same API.
--   * `org_roles` (0086) is per ORGANIZATION, because a role is one
--     organization's own vocabulary for its own members.
--   * What varies per organization is therefore exactly WHICH permissions a role
--     grants, and that is this row. It carries `organization_id` because the
--     role half of the pair does.
--
-- So this table needs the organization predicate every #97 table needs and 0091
-- does not: row-level security fences `(tenant, environment)` and NOTHING finer,
-- so the organization predicate that every read and every write repeats is the
-- only thing keeping one organization's mapping out of a sibling organization's
-- queries inside one environment. `organization_id` is DENORMALIZED from the
-- role endpoint, which already agrees with it, for the reason the header of
-- 0088 gives.
--
-- ---------------------------------------------------------------------------
-- (2) What the foreign keys prove, and what they DO NOT.
-- ---------------------------------------------------------------------------
-- Every endpoint id is globally unique and embeds its own scope, so the id-only
-- foreign keys below are the backstop that makes a mapping naming a NONEXISTENT
-- organization, role, or permission impossible (the 0084 precedent, restated in
-- 0089).
--
-- They prove existence and NOTHING else. In particular, and this is the part
-- worth stating exactly because a reader is likely to assume otherwise:
--
--   * The `permission_id` foreign key does NOT prove the permission belongs to
--     THIS environment. `permissions.id` is a GLOBAL primary key, so a `prm_`
--     id minted in another environment satisfies it perfectly.
--   * The `role_id` foreign key does NOT prove the role belongs to this
--     organization, or even to this environment.
--   * The `organization_id` foreign key does NOT prove the organization is in
--     this scope, or that it is the organization the role belongs to.
--   * A soft-deleted endpoint satisfies every one of them, because the row is
--     retained.
--
-- SAME-SCOPE and SAME-ORGANIZATION containment is therefore an APPLICATION
-- invariant that the repository resolves explicitly before every write: an
-- in-process scope check on each of the four caller-supplied identifiers, and
-- then a LIVE lookup of the role IN THE NAMED ORGANIZATION and of the permission
-- IN THIS SCOPE. Which of those layers is individually observable, and what
-- removing each one actually produces, is recorded on `ActingOrgRolePermissionRepo`
-- against measurements rather than against expectations.
--
-- The UPDATE grant below names EXACTLY the soft-delete pair, so none of that
-- containment can be undone after the fact: an existing mapping can never be
-- repointed at a different role, a different permission, a different
-- organization, or a different scope.
--
-- ---------------------------------------------------------------------------
-- (3) The live uniqueness key deliberately EXCLUDES `organization_id`.
-- ---------------------------------------------------------------------------
-- The key is `(tenant_id, environment_id, role_id, permission_id)`, matching
-- `org_group_roles_group_role_live_uniq` (0089:93-95), which likewise omits the
-- `organization_id` its table carries. Adding a column to a unique key WEAKENS
-- it, and the weaker form would admit two LIVE rows for one `(role, permission)`
-- pair carrying different organizations, which is not a feature: a role belongs
-- to exactly ONE organization, so the pair already determines the organization
-- and the extra column could only ever admit a corrupt duplicate. Keeping the
-- key narrow means the index refuses that row even if some future write path
-- forgot to resolve the role in its organization.
--
-- PARTIAL over live rows, so a detach frees the pair immediately, and every read
-- filters `deleted_at IS NULL` so the reads and this invariant agree on exactly
-- the live set.
--
-- ---------------------------------------------------------------------------
-- (4) Never revived, and why that matters more here than anywhere else.
-- ---------------------------------------------------------------------------
-- A mapping is removed by SOFT DELETE and is never REVIVED. Re-attaching a
-- previously detached permission inserts a FRESH row with a FRESH id, so the
-- audit history of the detachment is never overwritten by the row that replaces
-- it, and a detachment can never be quietly undone in place.
--
-- This is the same rule 0089 states for an assignment and 0091 states for a
-- permission, and the three compose: deleting a permission does NOT cascade
-- here, so a deleted permission leaves its mapping rows LIVE and the resolution
-- projection stops selecting them on `permissions.deleted_at IS NULL` alone. A
-- re-created permission of the same slug is a NEW id (0091 header), so it does
-- not inherit the dead one's mappings. Deleting a permission is a security
-- operation and must not be reversible in its authorization effects.
--
-- ---------------------------------------------------------------------------
-- (5) Covenant.
-- ---------------------------------------------------------------------------
-- The table is NOT capped. There is no count constraint, no quota check, no
-- counter column, and no advisory-lock-plus-COUNT gate anywhere: a project
-- covenant forbids any cap or paywall gate on how many permissions a role may
-- carry or on how many roles may carry one permission. Both are unlimited, in
-- both directions.
--
-- The tension issue #98 must keep unmistakable, restated here because this is
-- the second of the two tables where a cap would have to live: the byte and
-- count BUDGET a later PR of this issue adds is a SIZE BOUND ON ONE TOKEN. It is
-- never a cap on how many permissions may be STORED, attached, or resolved.
-- There is nothing in this file for such a cap to point at, and that absence is
-- the proof.
--
-- ---------------------------------------------------------------------------
-- (6) Classification and the delta vocabulary.
-- ---------------------------------------------------------------------------
-- Like the two join tables of 0089, this table has no `ResourceType` of its own:
-- it is a join row addressed through the role and the permission it maps, both
-- of which are classified, and neither of the 0089 join tables classifies
-- either. Nothing here travels in a config snapshot.
--
-- Every mutation of this table writes an audit_log row in the SAME transaction
-- as the mutation, through the store's single audited-write path, under one of
-- two actions: `organization.role.permission.assign` and
-- `organization.role.permission.unassign`. Those two action strings ARE the
-- delta contract for a mapping. They DO carry the `organization.` prefix that
-- 0091's three permission actions deliberately do not, and the difference is the
-- whole point of this table: the vocabulary is environment scoped and has no
-- organization dimension to name, while a mapping has one. There is deliberately
-- NO outbox table and no change feed here (that is M11; migration 0025 records
-- why a shared outbox built without a concrete consumer in view is very likely
-- the wrong shape). ADR 0002 is binding: which permissions a role grants is
-- always these rows, never a fold over events.
--
-- Migration safety obligation (see migrate.rs): `org_role_permissions` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH
-- CHECK, carries the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Grants are least-privilege and COLUMN-scoped for the
-- UPDATE (the #31 lesson). Every statement is additive (a new table, its
-- indexes, its policy, and its grants; no existing column is altered or
-- dropped), so this migration is an EXPAND.

CREATE TABLE org_role_permissions (
    -- The rpm_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization the ROLE belongs to (see (1) in the header). The
    -- permission half has no organization at all, so this column describes the
    -- role side of the pair and is what fences one organization's mapping from a
    -- sibling's inside one environment.
    organization_id text        NOT NULL,
    -- The role that grants the permission (a rol_ id of this organization).
    role_id         text        NOT NULL,
    -- The permission granted (a prm_ id of THIS ENVIRONMENT, with no
    -- organization of its own).
    permission_id   text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the permission was detached from the role (present only in a
    -- soft-deleted row). The row is RETAINED so the target of the two audit
    -- actions stays resolvable: an `organization.role.permission.unassign` row
    -- names this mapping's id, and a hard delete would leave that row pointing
    -- at an id nothing can look up. No foreign key enforces the retention and
    -- there deliberately is none: `audit_log` (0002) stores `target_id` as free
    -- text and references only `tenants` and `environments`, because an
    -- append-only audit trail must not be constrained by a data table's
    -- lifecycle. Retention is therefore an APPLICATION rule, and it is the same
    -- rule (4) in the header states from the other side: a detached mapping is
    -- never revived, so its detachment stays legible forever.
    deleted_at      timestamptz,
    CONSTRAINT org_role_permissions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Existence only; see (2) in the header for what these do NOT prove and
    -- where the containment invariant actually lives.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (role_id) REFERENCES org_roles (id),
    FOREIGN KEY (permission_id) REFERENCES permissions (id)
);

-- At most one LIVE mapping per (role, permission). PARTIAL over live rows, so
-- detaching frees the pair immediately. `organization_id` is deliberately NOT in
-- this key; see (3) in the header.
CREATE UNIQUE INDEX org_role_permissions_pair_live_uniq
    ON org_role_permissions (tenant_id, environment_id, role_id, permission_id)
    WHERE deleted_at IS NULL;

-- "Which permissions does this role grant": the admin list, and the join the
-- effective-permission resolution performs once the effective ROLE set is known,
-- so this index is on the token-issuance path. The (created_at, id) tail is the
-- stable pagination key the management list orders on, following 0089:99-100;
-- the partial predicate follows the live-uniqueness index above, because every
-- read on this table filters deleted rows out.
CREATE INDEX org_role_permissions_role_idx
    ON org_role_permissions (tenant_id, environment_id, role_id, created_at, id)
    WHERE deleted_at IS NULL;

-- "Which roles grant this permission": the permission-detail view, and the
-- blast-radius answer an operator wants BEFORE deleting a permission, mirroring
-- 0089:104-105.
CREATE INDEX org_role_permissions_permission_idx
    ON org_role_permissions (tenant_id, environment_id, permission_id, created_at, id)
    WHERE deleted_at IS NULL;

ALTER TABLE org_role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_role_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_role_permissions_tenant_isolation ON org_role_permissions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants. The CONTROL plane attaches (INSERT), lists (SELECT), and detaches
-- through a COLUMN-scoped UPDATE of EXACTLY the soft-delete pair. `role_id`,
-- `permission_id`, `organization_id`, the scope columns, and `id` are ABSENT
-- from the UPDATE list, so an existing mapping can never be REPOINTED (see (2)
-- in the header). DELETE is granted to nobody.
GRANT SELECT, INSERT ON org_role_permissions TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON org_role_permissions TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE, and the asymmetry with
-- `org_membership_roles` (0089:211-212) is deliberate and worth stating, because
-- a reader who has just read that migration will expect the soft-delete pair
-- here too. That table is keyed on a MEMBERSHIP, and the invitation-accept side
-- effect runs on the data plane: reviving a membership must strip its direct
-- role grants, so the accept transaction needs the column-scoped UPDATE there.
-- NO membership lifecycle reaches THIS table. It is keyed on a ROLE, exactly as
-- `org_group_roles` is keyed on a GROUP, so the data plane stays strictly READ
-- ONLY here (0089:128-131) and holds no INSERT, no UPDATE on any column, and no
-- DELETE. A data plane able to decide which capabilities a role grants is a data
-- plane able to write its own token claim, which is the whole threat these
-- grants exist to prevent. The SELECT is granted HERE, in the creating
-- migration, rather than deferred to the PR that first resolves a permission
-- set: the 0027-then-0084 revoke-and-re-grant churn on `organizations` is the
-- cautionary precedent for deferring a grant the design already knows it needs.
GRANT SELECT ON org_role_permissions TO ironauth_app;
