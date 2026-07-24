-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Organizations as first-class per-environment objects: the M10 data model
-- foundation (issue #94, PR-A). This migration extends the minimal organization
-- shell (0001 schema slot, 0027 soft-delete plus control-plane grants) with the
-- three additive pieces the B2B surface needs, and adds the one new state table
-- membership lives on. It changes NO flow or token path: it is a pure data-model
-- expand.
--
--   1. organizations.parent_id (nullable, self-referential). A tree-CAPABLE
--      organization graph without any tree BEHAVIOR: no cascade, no cycle check,
--      and no admin surface to set it (hierarchy execution is issue #103). The
--      column exists so the shape is stable from day one; same-scope validation is
--      an app-level concern for whenever a later PR ever sets it.
--   2. organizations.state ('active' or 'disabled'). The organization lifecycle
--      state, distinct from deleted_at (a soft delete) and from M5 tenant and
--      environment suspension. The disabled STATE lands here; the ENFORCEMENT
--      (blocking an org-context login) is a later PR. The control plane may toggle
--      it through a COLUMN-scoped UPDATE grant (the #31 least-privilege lesson).
--   3. A re-grant of SELECT on organizations to the data-plane role. 0027 revoked
--      every data-plane grant when the level was still a schema slot; membership
--      resolution and org-context validation both need the data plane to READ an
--      organization, so the read (and only the read) comes back.
--   4. org_memberships: the many-to-many join between a user and an organization,
--      a new tenant-scoped table. Multi-org from day one (nothing assumes one org
--      per user). RLS is ENABLEd and FORCEd, the (tenant, environment) isolation
--      policy and the nonempty-scope CHECK are pinned, and the table is registered
--      in scripts/query-audit.sh, exactly as every scoped table.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (org_memberships) ENABLEs and FORCEs row-level security, adds the (tenant,
-- environment) isolation policy, adds the nonempty-scope CHECK, and is registered
-- in scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The tree-capable parent pointer (schema only; issue #94).
--
-- Nullable and self-referential. The organization id is globally unique (a text
-- PRIMARY KEY that embeds its own scope), so an id-only foreign key is sufficient
-- to keep the pointer referentially sound; same-scope containment is validated in
-- the application whenever a later PR sets it (PR-A never does). No grant is added:
-- nothing writes this column yet, so neither plane needs a privilege on it.
ALTER TABLE organizations
    ADD COLUMN parent_id text;
ALTER TABLE organizations
    ADD CONSTRAINT organizations_parent_fk
    FOREIGN KEY (parent_id) REFERENCES organizations (id);

-- ---------------------------------------------------------------------------
-- 2. The organization lifecycle state (issue #94).
--
-- Defaults to 'active'; the closed CHECK set means an unknown state can never be
-- written. Distinct from deleted_at: a disabled organization still EXISTS and is
-- readable (get and list return it), it is merely marked disabled, whereas a
-- soft-deleted organization reads as absent.
ALTER TABLE organizations
    ADD COLUMN state text NOT NULL DEFAULT 'active';
ALTER TABLE organizations
    ADD CONSTRAINT organizations_state_valid
    CHECK (state IN ('active', 'disabled'));

-- The control plane toggles the lifecycle state through a COLUMN-scoped UPDATE of
-- EXACTLY the state column (never a table-wide UPDATE, the #31 lesson): the enable
-- and disable actions may set state, and nothing else on the row. The data plane is
-- never granted this: only an admin toggles an organization's state.
GRANT UPDATE (state) ON organizations TO ironauth_control;

-- ---------------------------------------------------------------------------
-- 3. Re-grant the data-plane READ on organizations (issue #94).
--
-- 0027 revoked every data-plane grant on organizations when the level was a schema
-- slot only. The B2B data model needs the data plane to READ an organization: to
-- validate an invitation's org-context and to resolve a membership's organization.
-- Only SELECT comes back (never INSERT, UPDATE, or DELETE): the organization
-- lifecycle stays entirely the control plane's, and the data plane can look an
-- organization up but never mutate one.
GRANT SELECT ON organizations TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 4. Organization membership: the user-to-organization join (issue #94).
--
-- One row per (organization, user) binding in a scope. A tenant-scoped table like
-- every other resource: mandatory tenant_id and environment_id, RLS below, and an
-- omb_ scoped identifier that embeds its (tenant, environment). Multi-org is native:
-- a user may hold many membership rows across organizations, and an organization
-- many across users. A removed membership soft-deletes (deleted_at), so the audit
-- foreign key to it stays satisfiable.
CREATE TABLE org_memberships (
    -- The omb_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization this membership belongs to (an org_ id).
    organization_id text        NOT NULL,
    -- The user this membership binds into the organization (a usr_ id).
    user_id         text        NOT NULL,
    -- The membership lifecycle state. A closed set that starts as just 'active'; a
    -- removed membership soft-deletes through deleted_at rather than adding a state.
    state           text        NOT NULL DEFAULT 'active',
    -- Free-form membership metadata (the issue's "state and metadata"). Structured
    -- JSON the admin surface reads and writes; never interpreted by the auth core.
    metadata        jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the membership was removed (present only in a soft-deleted row).
    deleted_at      timestamptz,
    CONSTRAINT org_memberships_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed lifecycle set: an unknown state can never be written.
    CONSTRAINT org_memberships_state_valid
        CHECK (state IN ('active')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The membership's organization must exist (the organization id is globally
    -- unique, so an id-only foreign key is sufficient). This is the backstop that
    -- makes a membership to a nonexistent or cross-scope organization impossible,
    -- even on the accept path where the org-context was validated up front.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    -- The membership's user must exist. A plain foreign key into users(id): users
    -- are soft-deleted, so a membership is never hard-deleted out from under a scope.
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- At most one LIVE membership per (organization, user) in a scope: a duplicate add
-- of a user already a live member is a storage-engine conflict, not an application
-- check. The index is PARTIAL over live rows (WHERE deleted_at IS NULL), so a
-- soft-deleted (removed) membership does NOT occupy the key: re-adding a removed
-- user REVIVES the dead row (create sets deleted_at back to NULL) rather than
-- tripping a permanent conflict, and every read (which filters deleted_at IS NULL)
-- and this uniqueness invariant agree on exactly the live set.
CREATE UNIQUE INDEX org_memberships_org_user_live_uniq
    ON org_memberships (tenant_id, environment_id, organization_id, user_id)
    WHERE deleted_at IS NULL;

-- The admin "who is in this organization" list reads a scope's memberships for one
-- organization ordered by the stable (created_at, id) key.
CREATE INDEX org_memberships_org_idx
    ON org_memberships (tenant_id, environment_id, organization_id, created_at, id);
-- The "which organizations is this user in" list (multi-org) reads a scope's
-- memberships for one user ordered by the stable (created_at, id) key.
CREATE INDEX org_memberships_user_idx
    ON org_memberships (tenant_id, environment_id, user_id, created_at, id);

ALTER TABLE org_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY org_memberships_tenant_isolation ON org_memberships
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
-- The CONTROL plane owns the admin membership surface: it lists and inspects
-- memberships (SELECT), adds one (INSERT), and removes one through a COLUMN-scoped
-- UPDATE of EXACTLY the mutable columns (state, metadata, updated_at, deleted_at),
-- never a table-wide UPDATE that could rewrite the scope, the organization, or the
-- user of an existing row (the #31 lesson).
GRANT SELECT, INSERT ON org_memberships TO ironauth_control;
GRANT UPDATE (state, metadata, updated_at, deleted_at)
    ON org_memberships TO ironauth_control;

-- The DATA plane binds a member on the invitation-accept path (the invitee redeems a
-- token that carried an org-context, and the accept binds them into the organization
-- in the SAME transaction as the pending -> accepted flip). That bind is a
-- revive-or-insert: a fresh member is an INSERT, and a member the admin previously
-- removed is REVIVED through a COLUMN-scoped UPDATE of exactly the same mutable
-- columns the control plane may write (state, metadata, updated_at, deleted_at back to
-- NULL), so a removed member re-accepting is re-bound rather than blocked. The grant
-- is COLUMN-scoped (never a table-wide UPDATE that could rewrite the scope, the
-- organization, or the user of a row, the #31 lesson), and DELETE is never granted:
-- the data plane can bind and read a membership, but the row is only ever hard-removed
-- by nobody (soft delete is the admin's remove). SELECT also serves a later PR's
-- membership resolution at login.
GRANT SELECT, INSERT ON org_memberships TO ironauth_app;
GRANT UPDATE (state, metadata, updated_at, deleted_at)
    ON org_memberships TO ironauth_app;
