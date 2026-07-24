-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Organization groups (issue #97, milestone M10).
--
-- Creates `org_groups`: a named group scoped to one organization, carrying a
-- NULLABLE self-referential `parent_id` that forms a per-organization FOREST. A
-- group in this issue is a NAME and a POSITION IN A TREE only. Binding a
-- membership into a group and assigning a role to a group are the following
-- migrations of this issue and add no column here.
--
--   1. `parent_id` is LIVE, and that is the one thing that makes this table
--      different from every other table in this schema. Contrast
--      `organizations.parent_id`, added deliberately INERT by 0084 for issue
--      #103: nothing reads or writes it. This column IS read and written, and
--      the repository runs a write-time cycle check and a configurable depth
--      bound under a per-organization advisory lock before any value lands in
--      it. The two trees are ENTIRELY DISTINCT (an organization tree and a group
--      tree) and must never be conflated by a later reader.
--   2. The group tree is a SINGLE-PARENT tree, not a multi-parent graph. There
--      is no edge table: a group has at most one parent, so "ancestor" is a
--      chain and "depth" is unambiguous. A multi-parent model would need a
--      separate edge table, full reachability rather than a chain walk, and a
--      resolution closure that fans out multiplicatively on the token-issuance
--      path. Adding an edge table later is additive; removing one is not.
--   3. The table carries an immutable `slug` (the stable name a token claim and
--      a future journey predicate will travel under) alongside a mutable
--      `display_name`, exactly as `org_roles` does in 0086, and for the same
--      reason: a rename must never change an authorization or routing decision.
--      The slug charset is restricted to lowercase ASCII with NO case folding,
--      so slug comparison is byte exact and deliberately does NOT route through
--      the identifier canonicalization seam
--      (crates/ironauth-store/src/identifier.rs).
--   4. The table is NOT capped. There is no count constraint, no quota check,
--      and no advisory-lock-plus-COUNT gate anywhere: a project covenant forbids
--      any cap or paywall gate on the number of groups an organization may
--      define. The configurable `max_group_depth` bounds tree DEPTH only, never
--      the NUMBER of groups: an organization may hold unlimited groups at any
--      one depth level. The advisory lock this table's writes take is a
--      SERIALIZATION device for the cycle check, NOT a counting gate, and must
--      not be mistaken for the dynamic-registration quota pattern it superficially
--      resembles.
--
-- Why the one-node cycle is a CHECK and longer cycles are not. A group being its
-- own parent is expressible as a row-local predicate, so the storage engine
-- refuses it unconditionally (`org_groups_parent_not_self`). A cycle of length
-- two or more is a property of the whole edge set and is NOT expressible as a
-- CHECK; it is refused by the repository's bounded recursive ancestor walk,
-- taken under a per-organization transaction-scoped advisory lock so two
-- concurrent reparents cannot each observe an acyclic graph and jointly close a
-- loop. A raising TRIGGER is deliberately NOT used: `RAISE EXCEPTION` aborts the
-- transaction, and every mutation in this schema must write its audit row AFTER
-- the mutation and BEFORE the commit, so a raising trigger would make the audit
-- insert impossible (SQLSTATE 25P02). The CHECK below is therefore a
-- defense-in-depth latch that the application path never reaches: the Rust cycle
-- check refuses `parent = self` first.
--
-- The delta vocabulary (issue #97, and what milestone M11 will consume). Every
-- mutation of this table writes an audit_log row in the SAME transaction as the
-- mutation, through the store's single audited-write path, under one of four
-- actions: `organization.group.create`, `organization.group.update`,
-- `organization.group.delete`, and `organization.group.reparent`. Those four
-- action strings ARE the delta contract for a group. The reparent action
-- additionally records the new parent in the audit row's operator-safe `detail`
-- dimension, because reparenting silently changes the effective roles of every
-- descendant and the history is otherwise unreconstructable. There is
-- deliberately NO outbox table and no change feed here: IronAuth has no eventing
-- delivery surface yet (that is M11), and migration 0025 records why a shared
-- outbox built without a concrete consumer in view is very likely the wrong
-- shape. Delivery is deferred, not stubbed. ADR 0002 is binding: the current
-- shape of the group tree is always its rows, never a fold over events.
--
-- Migration safety obligation (see migrate.rs): `org_groups` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH
-- CHECK, carries the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Grants are least-privilege and COLUMN-scoped for the
-- UPDATE (the #31 lesson). Every statement is additive (a new table, its
-- indexes, its policy, and its grants; no existing column is altered or
-- dropped), so this migration is an EXPAND.

CREATE TABLE org_groups (
    -- The grp_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization this group belongs to (an org_ id).
    organization_id text        NOT NULL,
    -- The parent group, or NULL for a root. The foreign key is id-only (a group
    -- id is globally unique and embeds its own scope), so the database refuses a
    -- parent that does not exist. SAME-ORGANIZATION containment is an
    -- APPLICATION invariant the repository enforces explicitly before every
    -- write, exactly as cross-organization isolation is for org_memberships: the
    -- row-level-security policy fences (tenant, environment) only, so nothing in
    -- the database stops two organizations of ONE environment from being wired
    -- together. Every statement that reads or writes this column therefore
    -- repeats organization_id explicitly.
    parent_id       text,
    -- The IMMUTABLE stable name (see org_roles.slug in 0086). Never granted in
    -- any UPDATE column list below.
    slug            text        NOT NULL,
    -- The mutable human-facing label the admin console shows.
    display_name    text        NOT NULL,
    -- Free-form group metadata the admin surface reads and writes; never
    -- interpreted by the auth core.
    metadata        jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the group was deleted (present only in a soft-deleted row). The row is
    -- retained so the audit foreign key to it stays satisfiable.
    deleted_at      timestamptz,
    CONSTRAINT org_groups_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The restricted slug charset: lowercase ASCII alphanumeric plus dot,
    -- underscore, and ASCII hyphen, starting alphanumeric, at most 63
    -- characters. No case folding, so comparison is byte exact. The ASCII hyphen
    -- U+002D is deliberate and is not prose punctuation (scripts/dash-scan.sh
    -- targets only the em and en dashes).
    CONSTRAINT org_groups_slug_valid
        CHECK (slug ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    CONSTRAINT org_groups_display_name_nonempty
        CHECK (display_name <> ''),
    -- The cheapest possible cycle guard, enforced by the storage engine: a group
    -- is never its own parent. Longer cycles are NOT expressible as a CHECK and
    -- are refused by the repository's write-time walk (see the header). This
    -- constraint closes the one-node case unconditionally and is unreachable from
    -- the application path.
    CONSTRAINT org_groups_parent_not_self
        CHECK (parent_id IS NULL OR parent_id <> id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The group's organization must exist. The organization id is globally
    -- unique and embeds its own scope, so an id-only foreign key is sufficient
    -- and is the backstop that makes a group in a nonexistent or cross-scope
    -- organization impossible (the 0084 precedent).
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT org_groups_parent_fk
        FOREIGN KEY (parent_id) REFERENCES org_groups (id)
);

-- At most one LIVE group per (organization, slug). The index is PARTIAL over
-- live rows, so a soft-deleted group does NOT occupy its slug and the name can
-- be used again by a NEW group; every read filters deleted_at IS NULL, so the
-- reads and this uniqueness invariant agree on exactly the live set.
--
-- As with org_roles (0086), re-creating a deleted group inserts a FRESH row with
-- a FRESH id rather than reviving the dead one: later migrations of this issue
-- hang group MEMBERSHIPS and role ASSIGNMENTS off a group id, so reviving a
-- deleted group would silently restore every one of them. Deleting a group is a
-- security operation and must not be quietly reversible in its authorization
-- effects.
CREATE UNIQUE INDEX org_groups_org_slug_live_uniq
    ON org_groups (tenant_id, environment_id, organization_id, slug)
    WHERE deleted_at IS NULL;

-- The admin "groups in this organization" list, on the stable (created_at, id)
-- pagination key.
CREATE INDEX org_groups_org_idx
    ON org_groups (tenant_id, environment_id, organization_id, created_at, id);

-- The DOWNWARD traversal index. The recursive DESCENDANT walk (the subtree-height
-- half of the depth bound) joins each child's parent_id against the current
-- frontier, so parent_id must lead after the scope columns. Without this the
-- descendant walk degrades to a sequential scan of the environment's whole group
-- set per level. The UPWARD ancestor walk needs no index of its own: each step is
-- a primary-key lookup on id.
CREATE INDEX org_groups_parent_idx
    ON org_groups (tenant_id, environment_id, parent_id)
    WHERE deleted_at IS NULL;

ALTER TABLE org_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY org_groups_tenant_isolation ON org_groups
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants.
--
-- The CONTROL plane owns the admin group surface: list and inspect (SELECT),
-- create (INSERT), and rename, reparent, or delete through a COLUMN-scoped
-- UPDATE of EXACTLY the mutable columns. `parent_id` IS in that list, because
-- reparenting is an admin operation. `slug` is deliberately ABSENT (see the
-- column comment): the stable name is immutable by GRANT. `organization_id`,
-- `tenant_id`, `environment_id`, and `id` are likewise absent, so a group row can
-- never be moved between scopes or between organizations, which is what keeps the
-- same-organization containment invariant from being defeatable by an UPDATE
-- after the fact. DELETE is granted to nobody on either plane: removal is the
-- soft delete.
GRANT SELECT, INSERT ON org_groups TO ironauth_control;
GRANT UPDATE (display_name, metadata, parent_id, updated_at, deleted_at)
    ON org_groups TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE: a later PR of this issue walks
-- the group ancestry to resolve a subject's effective roles on the token-issuance
-- path, which runs under the low-privilege app role. No data-plane path ever
-- writes a group, so INSERT, UPDATE, and DELETE are granted to nobody there. The
-- SELECT is granted HERE, in the creating migration, rather than being deferred
-- to the PR that first needs it: the 0027-then-0084 revoke-and-re-grant churn on
-- `organizations` is the cautionary precedent for deferring a grant the design
-- already knows it needs.
GRANT SELECT ON org_groups TO ironauth_app;
