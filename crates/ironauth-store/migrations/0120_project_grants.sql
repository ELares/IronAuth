-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Project grants (issue #102, milestone M10).
--
-- The B2B delegation contract as DATA rather than custom code: a vendor owns an
-- application, a customer organization self-administers its own users against it, and
-- the vendor bounds which roles that customer's administrators may hand out. Zitadel is
-- the prior art and the only OSS implementation that ships it.
--
-- The adaptation this schema makes, which is the one design decision here worth
-- arguing about. In Zitadel a role belongs to the PROJECT, so a grant hands a customer
-- organization a subset of somebody else's roles. In IronAuth a role belongs to an
-- ORGANIZATION (see 0089): `org_roles.organization_id` is NOT NULL and every assignment
-- surface is keyed within one organization. So a grant here cannot hand over foreign
-- roles, and does not try to. It names a subset of the organization's OWN roles, and
-- the meaning is "of the roles this organization has, these are the ones a DELEGATED
-- administrator may assign". That is exactly the acceptance criterion, and it is
-- expressible against the role model that shipped rather than requiring a second one.
--
--   1. ABSENCE MEANS UNRESTRICTED, and this is the upgrade-safety property. An
--      organization with no live grant is administered exactly as it is today. Only a
--      grant that EXISTS restricts, so applying this migration changes no behaviour for
--      anybody, and the restriction is something an operator opts into per (application,
--      organization) pair. The alternative default, "no grant means no assignable
--      roles", would silently break every delegated administrator in every environment
--      at upgrade. Migration 0118 made the same call for management-credential
--      permissions and for the same reason.
--   2. A grant with an EMPTY role subset is meaningful and is NOT the same as no grant:
--      it says this organization's delegated administrators may assign NOTHING. That is
--      a legitimate contract (a customer who self-administers membership but never
--      roles), so no CHECK requires the subset to be nonempty. Reading an empty subset
--      as "unrestricted" would make the most restrictive intent expressible only by
--      deleting the grant, which is backwards.
--   3. The subset is a TABLE, not a `text[]` column on the grant. An array cannot carry
--      a foreign key, and the invariant that matters most here is that a granted role
--      still EXISTS: a subset naming a deleted role would silently widen or narrow
--      depending on how the resolver treated the miss. A join row with a real
--      `REFERENCES org_roles (id)` makes that unrepresentable. 0118 could use an array
--      because its members are permission SLUGS from a closed enum owned by the code,
--      with no row to dangle from.
--   4. No ON DELETE anywhere, so every foreign key is RESTRICT. CASCADE on the
--      organization or the client would silently delete a grant, and deleting a grant
--      WIDENS what a delegated administrator may assign (point 1). A destructive action
--      whose blast radius is "somebody's authority quietly grew" must be explicit, so
--      removing a grant is its own audited operation. This is the same argument
--      migration 0119 makes about confinement.
--   5. Same-organization containment between a grant and its granted roles is an
--      APPLICATION invariant the repository resolves before every write, exactly as
--      0089 does for the three endpoints of an assignment. The id-only foreign keys are
--      the backstop that makes a grant naming a nonexistent role impossible; they
--      cannot by themselves express "and that role belongs to THIS organization".
--
-- Migration safety obligation (see migrate.rs): both tables are NEW TENANT-SCOPED
-- tables, so each ENABLEs and FORCEs row-level security, carries the (tenant,
-- environment) isolation policy with byte-identical USING and WITH CHECK, carries the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Grants are
-- least-privilege and COLUMN-scoped for the UPDATE (the #31 lesson). Every statement is
-- additive, so this migration is an EXPAND.

CREATE TABLE project_grants (
    -- The pgt_ scoped identifier; embeds its (tenant, environment).
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The application the grant is about (a cli_ id): the vendor's project.
    client_id       text        NOT NULL,
    -- The customer organization whose delegated administrators this grant bounds.
    organization_id text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the grant was withdrawn (present only in a soft-deleted row). The row is
    -- retained rather than deleted for a reason that IS a foreign key, though not an
    -- audit one: `project_grant_roles.grant_id` references this id, so a hard delete
    -- would have to take the subset with it and the record of what was once assignable
    -- would go too. Nothing in `audit_log` references this table (migration 0002 gives
    -- it foreign keys to `tenants` and `environments` and to nothing else), so audit
    -- retention here is an APPLICATION rule: the audited action carries this id as its
    -- target, and a target that no longer resolves is a hole in the history rather than
    -- a constraint violation.
    deleted_at      timestamptz,
    CONSTRAINT project_grants_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (client_id) REFERENCES clients (id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- At most one LIVE grant per (client, organization). PARTIAL over live rows, so
-- withdrawing a grant frees the pair immediately and a fresh grant is a fresh row with
-- a fresh id rather than a revival, which keeps the withdrawal's audit history intact
-- (the 0089 point 3 rule, applied here).
CREATE UNIQUE INDEX project_grants_client_org_live_uniq
    ON project_grants (tenant_id, environment_id, client_id, organization_id)
    WHERE deleted_at IS NULL;

-- "Is this organization under a grant, and which": the lookup the assignment path
-- performs before every delegated role assignment, so this index is on a write path
-- that runs per assignment.
CREATE INDEX project_grants_organization_idx
    ON project_grants (tenant_id, environment_id, organization_id, created_at, id);

-- "Which organizations hold a grant on this application": the vendor's own view, and
-- the blast-radius answer before an application is retired.
CREATE INDEX project_grants_client_idx
    ON project_grants (tenant_id, environment_id, client_id, created_at, id);

ALTER TABLE project_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY project_grants_tenant_isolation ON project_grants
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants. The CONTROL plane creates (INSERT), lists (SELECT), and withdraws through a
-- COLUMN-scoped UPDATE of EXACTLY the soft-delete pair. `client_id`,
-- `organization_id`, the scope columns, and `id` are ABSENT from the UPDATE list, so a
-- live grant can never be REPOINTED at a different application or a different
-- organization: re-pointing would move a bound set of assignable roles onto a customer
-- who was never granted them, without any row recording that it happened. DELETE is
-- granted to nobody.
GRANT SELECT, INSERT ON project_grants TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON project_grants TO ironauth_control;

-- The DATA plane gets NOTHING on this table, deliberately. A project grant bounds what
-- a delegated administrator may ASSIGN, which is a management-plane act on the control
-- plane. Token issuance resolves effective roles from the assignment tables (0089) and
-- never consults this one: by the time a token is minted the grant has already had its
-- say, in the form of which assignment rows exist. Granting the data plane SELECT here
-- would widen the token-issuance role's reach for no path that needs it.

CREATE TABLE project_grant_roles (
    -- The pgr_ scoped identifier; embeds its (tenant, environment).
    id              text        NOT NULL PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The grant this role is a member of (a pgt_ id).
    grant_id        text        NOT NULL,
    -- The organization the grant and the role both belong to, DENORMALIZED from the
    -- grant exactly as 0089 denormalizes it onto an assignment: row-level security
    -- fences (tenant, environment) and nothing finer, so this column is what keeps one
    -- organization's granted subset out of a sibling's queries inside one environment.
    organization_id text        NOT NULL,
    -- The assignable role (a rol_ id of that organization).
    role_id         text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT project_grant_roles_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (grant_id) REFERENCES project_grants (id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (role_id) REFERENCES org_roles (id)
);

-- At most one LIVE membership per (grant, role). PARTIAL over live rows.
CREATE UNIQUE INDEX project_grant_roles_grant_role_live_uniq
    ON project_grant_roles (tenant_id, environment_id, grant_id, role_id)
    WHERE deleted_at IS NULL;

-- "Which roles may a delegated administrator under this grant assign": the read the
-- assignment path performs, so this index is on that write path.
CREATE INDEX project_grant_roles_grant_idx
    ON project_grant_roles (tenant_id, environment_id, grant_id, created_at, id);

-- "Which grants make this role assignable": the blast-radius answer BEFORE a role is
-- deleted, which the role-detail view needs for the same reason 0089 indexes its own
-- role direction.
CREATE INDEX project_grant_roles_role_idx
    ON project_grant_roles (tenant_id, environment_id, role_id, created_at, id);

ALTER TABLE project_grant_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_grant_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY project_grant_roles_tenant_isolation ON project_grant_roles
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants on the CONTROL plane, identical in shape to project_grants above and for
-- identical reasons: `grant_id`, `role_id`, `organization_id`, the scope columns and
-- `id` are all absent from the UPDATE list, so a membership can never be repointed at
-- a different role. Widening a subset is an INSERT and narrowing it is a soft delete,
-- and both leave a row behind.
GRANT SELECT, INSERT ON project_grant_roles TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON project_grant_roles TO ironauth_control;

-- The DATA plane gets nothing here either, for the reason given on project_grants.
