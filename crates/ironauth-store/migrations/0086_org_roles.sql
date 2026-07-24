-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Organization roles (issue #97, milestone M10).
--
-- Creates `org_roles`: a named role scoped to one organization. A role in this
-- issue is a NAME ONLY. Permission slugs and the role-to-permission mapping are
-- issue #98 and add no column here; attaching a role to a service-account
-- principal is issue #99 and adds no column here either.
--
--   1. The table carries an immutable `slug` (the stable name a token claim will
--      travel under) alongside a mutable `display_name`. A rename therefore never
--      changes an authorization decision. The slug charset is restricted to
--      lowercase ASCII with NO case folding, so slug comparison is byte exact and
--      deliberately does NOT route through the identifier canonicalization seam
--      (crates/ironauth-store/src/identifier.rs). A later reader must not "fix"
--      it into that seam: the two have different jobs, and folding a role name
--      would make two distinct roles collide.
--   2. The table is NOT capped. There is no count constraint, no quota check, and
--      no advisory-lock-plus-COUNT gate anywhere: a project covenant forbids any
--      cap or paywall gate on the number of roles an organization may define.
--   3. Groups, group membership, and the two role-assignment surfaces are the
--      following migrations of this issue. This migration adds roles only.
--
-- The delta vocabulary (issue #97, and what milestone M11 will consume). Every
-- mutation of this table writes an audit_log row in the SAME transaction as the
-- mutation, through the store's single audited-write path, under one of three
-- actions: `organization.role.create`, `organization.role.update`, and
-- `organization.role.delete`. Those three action strings ARE the delta contract
-- for a role. There is deliberately NO outbox table and no change feed here:
-- IronAuth has no eventing delivery surface yet (that is M11), and migration
-- 0025 records why a shared outbox built without a concrete consumer in view is
-- very likely the wrong shape. Delivery is deferred, not stubbed. Note also that
-- ADR 0002 is binding: the current value of a role is always its row, never a
-- fold over events, so no reader may reconstruct roles from the audit log.
--
-- Migration safety obligation (see migrate.rs): `org_roles` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH
-- CHECK, carries the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Grants are least-privilege and COLUMN-scoped for the
-- UPDATE (the #31 lesson). Every statement is additive (a new table, its indexes,
-- its policy, and its grants; no existing column is altered or dropped), so this
-- migration is an EXPAND.

CREATE TABLE org_roles (
    -- The rol_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization this role belongs to (an org_ id).
    organization_id text        NOT NULL,
    -- The IMMUTABLE stable name. This is what a token claim will carry, so a
    -- rename of display_name never changes an authorization decision. It is
    -- never granted in any UPDATE column list below, which makes the
    -- immutability a GRANT property rather than a convention: no code path,
    -- present or future, can rewrite it without a migration that says so.
    slug            text        NOT NULL,
    -- The mutable human-facing label the admin console shows. Renaming a role
    -- writes exactly this column (and updated_at).
    display_name    text        NOT NULL,
    -- Free-form role metadata the admin surface reads and writes; never
    -- interpreted by the auth core.
    metadata        jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the role was deleted (present only in a soft-deleted row). A deleted
    -- role is retained so the audit foreign key to it stays satisfiable.
    deleted_at      timestamptz,
    CONSTRAINT org_roles_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The restricted slug charset: lowercase ASCII alphanumeric plus dot,
    -- underscore, and ASCII hyphen, starting alphanumeric, at most 63 characters.
    -- No case folding, so comparison is byte exact. The ASCII hyphen U+002D is
    -- deliberate and is not prose punctuation (scripts/dash-scan.sh targets only
    -- the em and en dashes).
    CONSTRAINT org_roles_slug_valid
        CHECK (slug ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    CONSTRAINT org_roles_display_name_nonempty
        CHECK (display_name <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The role's organization must exist. The organization id is globally unique
    -- and embeds its own scope, so an id-only foreign key is sufficient and is
    -- the backstop that makes a role in a nonexistent or cross-scope
    -- organization impossible (the 0084 precedent).
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- At most one LIVE role per (organization, slug). The index is PARTIAL over live
-- rows, so a soft-deleted role does NOT occupy its slug and the name can be used
-- again by a NEW role; every read filters deleted_at IS NULL, so the reads and
-- this uniqueness invariant agree on exactly the live set.
--
-- Note the deliberate difference from org_memberships (0084): re-creating a
-- deleted role inserts a FRESH row with a FRESH id, it does not revive the dead
-- one. A membership revives because its identity is the (organization, user)
-- pair. A role's identity is its id, and later migrations of this issue hang
-- role ASSIGNMENTS off that id, so reviving a deleted role would silently
-- restore every assignment that pointed at it. Deleting a role is a security
-- operation and must not be quietly reversible in its authorization effects.
CREATE UNIQUE INDEX org_roles_org_slug_live_uniq
    ON org_roles (tenant_id, environment_id, organization_id, slug)
    WHERE deleted_at IS NULL;

-- The admin "roles in this organization" list, on the stable (created_at, id)
-- pagination key.
CREATE INDEX org_roles_org_idx
    ON org_roles (tenant_id, environment_id, organization_id, created_at, id);

ALTER TABLE org_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY org_roles_tenant_isolation ON org_roles
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
-- The CONTROL plane owns the admin role surface: list and inspect (SELECT),
-- create (INSERT), and rename or delete through a COLUMN-scoped UPDATE of
-- EXACTLY the mutable columns. `slug` is deliberately ABSENT from that list (see
-- the column comment): the stable name is immutable by GRANT. `organization_id`,
-- `tenant_id`, `environment_id`, and `id` are likewise absent, so a role row can
-- never be moved between scopes or between organizations (the #31 lesson).
-- DELETE is granted to nobody on either plane: removal is the soft delete.
GRANT SELECT, INSERT ON org_roles TO ironauth_control;
GRANT UPDATE (display_name, metadata, updated_at, deleted_at)
    ON org_roles TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE: a later PR of this issue
-- resolves a subject's effective roles on the token-issuance path, which runs
-- under the low-privilege app role. No data-plane path ever writes a role, so
-- INSERT, UPDATE, and DELETE are granted to nobody there. The SELECT is granted
-- HERE, in the creating migration, rather than being deferred to the PR that
-- first needs it: the 0027-then-0084 revoke-and-re-grant churn on
-- `organizations` is the cautionary precedent for deferring a grant the design
-- already knows it needs.
GRANT SELECT ON org_roles TO ironauth_app;
