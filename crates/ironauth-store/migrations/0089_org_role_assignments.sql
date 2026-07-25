-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Organization role assignments (issue #97, milestone M10).
--
-- Creates the TWO surfaces that actually grant a role, and nothing else:
--
--   * `org_group_roles`: a role granted to a GROUP. Every live member of that
--     group holds it, and so does every member of every DESCENDANT of that group,
--     because roles flow DOWN the group forest. This is the only inheriting
--     surface in the model.
--   * `org_membership_roles`: a role granted DIRECTLY to one org membership, with
--     no group involved.
--
-- The two tables are structurally identical modulo the subject column, and that is
-- deliberate: the resolution query unions them, so a shape difference between them
-- would become a case analysis on the token-issuance path. They are ONE migration
-- because they are ONE logical expand (the assignment surface); splitting them
-- would produce two migrations neither of which is independently meaningful.
--
--   1. Both tables carry `organization_id`, DENORMALIZED from their endpoints,
--      which already agree on it. Row-level security fences (tenant, environment)
--      and NOTHING finer, so the organization predicate that every read and every
--      write repeats is the only thing keeping one organization's assignments out
--      of a sibling organization's queries inside one environment.
--   2. Neither table is capped. There is no count constraint, no quota check, and
--      no advisory-lock-plus-COUNT gate anywhere: a project covenant forbids any
--      cap or paywall gate on how many roles a group or a membership may hold, or
--      on how many subjects a role may be granted to. All of those are unlimited.
--   3. An assignment is REMOVED by soft delete and is never REVIVED. Re-assigning a
--      previously unassigned role inserts a FRESH row with a FRESH id, so the audit
--      history of the unassignment is never overwritten by the row that replaces
--      it, and an unassignment can never be quietly undone in place.
--   4. `org_membership_roles` shares `org_group_members`' dependence on a
--      membership's lifecycle: removing an org membership CASCADES a soft delete
--      over this table too, so a removed and re-added user (whose membership row is
--      REVIVED with its original id) comes back with no direct roles. See the
--      header of migration 0088 for the whole argument.
--
-- The delta vocabulary (issue #97, and what milestone M11 will consume). Every
-- mutation of these tables writes an audit_log row in the SAME transaction as the
-- mutation, through the store's single audited-write path, under one of four
-- actions: `organization.group.role.assign`,
-- `organization.group.role.unassign`, `organization.membership.role.assign`, and
-- `organization.membership.role.unassign`. The membership cascade additionally
-- writes `organization.membership.attachments.revoke` against the MEMBERSHIP,
-- carrying an operator-safe count of what it stripped. Those action strings ARE the
-- delta contract for an assignment. There is deliberately NO outbox table and no
-- change feed here: IronAuth has no eventing delivery surface yet (that is M11),
-- and migration 0025 records why a shared outbox built without a concrete consumer
-- in view is very likely the wrong shape. Delivery is deferred, not stubbed. ADR
-- 0002 is binding: who holds which role is always these rows, never a fold over
-- events.
--
-- Migration safety obligation (see migrate.rs): both tables are NEW TENANT-SCOPED
-- tables, so each ENABLEs and FORCEs row-level security, carries the (tenant,
-- environment) isolation policy with byte-identical USING and WITH CHECK, carries
-- the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Grants are
-- least-privilege and COLUMN-scoped for the UPDATE (the #31 lesson). Every
-- statement is additive, so this migration is an EXPAND.

CREATE TABLE org_group_roles (
    -- The grl_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization both endpoints belong to (see the header).
    organization_id text        NOT NULL,
    -- The group the role is granted to (a grp_ id of this organization).
    group_id        text        NOT NULL,
    -- The role granted (a rol_ id of this organization).
    role_id         text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the assignment was withdrawn (present only in a soft-deleted row). The
    -- row is retained so the audit foreign key to it stays satisfiable.
    deleted_at      timestamptz,
    CONSTRAINT org_group_roles_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Each endpoint's id is globally unique and embeds its own scope, so id-only
    -- foreign keys are sufficient and are the backstop that makes an assignment
    -- naming a nonexistent or cross-scope group, role, or organization impossible
    -- (the 0084 precedent). SAME-ORGANIZATION containment between the three is an
    -- APPLICATION invariant the repository resolves explicitly before every write.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (group_id) REFERENCES org_groups (id),
    FOREIGN KEY (role_id) REFERENCES org_roles (id)
);

-- At most one LIVE assignment per (group, role). PARTIAL over live rows, so
-- unassigning frees the pair immediately (see header point 3).
CREATE UNIQUE INDEX org_group_roles_group_role_live_uniq
    ON org_group_roles (tenant_id, environment_id, group_id, role_id)
    WHERE deleted_at IS NULL;

-- "Which roles does this group grant": the join effective-role resolution performs
-- once the ancestor closure is known, so this index is on the token-issuance path.
CREATE INDEX org_group_roles_group_idx
    ON org_group_roles (tenant_id, environment_id, group_id, created_at, id);

-- "Which groups grant this role": the role-detail view, and the blast-radius answer
-- an operator wants BEFORE deleting a role.
CREATE INDEX org_group_roles_role_idx
    ON org_group_roles (tenant_id, environment_id, role_id, created_at, id);

ALTER TABLE org_group_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_group_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY org_group_roles_tenant_isolation ON org_group_roles
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants. The CONTROL plane assigns (INSERT), lists (SELECT), and unassigns through
-- a COLUMN-scoped UPDATE of EXACTLY the soft-delete pair. `group_id`, `role_id`,
-- `organization_id`, the scope columns, and `id` are ABSENT from the UPDATE list, so
-- an existing assignment can never be REPOINTED at a different group, a different
-- role, a different organization, or a different scope: the containment checked when
-- the row was written cannot be undone afterwards. DELETE is granted to nobody.
GRANT SELECT, INSERT ON org_group_roles TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON org_group_roles TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE: this is the table effective-role
-- resolution reads for the inherited half of the answer, on the token-issuance path,
-- under the low-privilege app role. No data-plane path ever writes an assignment.
GRANT SELECT ON org_group_roles TO ironauth_app;

CREATE TABLE org_membership_roles (
    -- The mrl_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization both endpoints belong to (see the header).
    organization_id text        NOT NULL,
    -- The org membership the role is granted to (an omb_ id of this organization),
    -- never a bare user id: a direct role assignment PRESUPPOSES organization
    -- membership structurally, exactly as a group binding does.
    membership_id   text        NOT NULL,
    -- The role granted (a rol_ id of this organization).
    role_id         text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    CONSTRAINT org_membership_roles_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (membership_id) REFERENCES org_memberships (id),
    FOREIGN KEY (role_id) REFERENCES org_roles (id)
);

-- At most one LIVE assignment per (membership, role). PARTIAL over live rows.
CREATE UNIQUE INDEX org_membership_roles_membership_role_live_uniq
    ON org_membership_roles (tenant_id, environment_id, membership_id, role_id)
    WHERE deleted_at IS NULL;

-- "Which roles does this membership hold directly": the DIRECT half of
-- effective-role resolution, so this index is on the token-issuance path. It is also
-- the predicate the membership cascade uses to find what to strip.
CREATE INDEX org_membership_roles_membership_idx
    ON org_membership_roles (tenant_id, environment_id, membership_id, created_at, id);

-- "Which members hold this role directly": the role-detail view and the
-- blast-radius answer before a role is deleted.
CREATE INDEX org_membership_roles_role_idx
    ON org_membership_roles (tenant_id, environment_id, role_id, created_at, id);

ALTER TABLE org_membership_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_membership_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY org_membership_roles_tenant_isolation ON org_membership_roles
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants on the CONTROL plane, identical in shape to org_group_roles above and for
-- identical reasons.
GRANT SELECT, INSERT ON org_membership_roles TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON org_membership_roles TO ironauth_control;

-- The DATA plane's grant on THIS table is deliberately wider than its grant on
-- org_group_roles above, and the asymmetry is the point. Both tables are read at
-- token issuance, so both need SELECT. But this table is keyed on a MEMBERSHIP, and
-- the invitation-accept side effect runs on the data plane (which is why 0084 grants
-- the same shape on `org_memberships`): accepting an invitation REVIVES a previously
-- removed membership, keeping its original id, and a revived membership must come
-- back holding no direct roles. So the accept transaction has to be able to revoke
-- this table's rows, and gets the COLUMN-scoped soft-delete pair to do it. Without
-- that grant the accept path would fail with SQLSTATE 42501, and the only ways to
-- make it succeed again would be to drop the cascade there (the silent hole where a
-- removed user restores every role by redeeming an old invitation) or to move the
-- accept side effect to the control plane.
--
-- `org_group_roles` needs none of this and gets none of it: it is keyed on a GROUP,
-- no membership lifecycle reaches it, and the data plane therefore stays strictly
-- READ ONLY there. Even here the data plane holds no INSERT (it can never create an
-- assignment), no UPDATE on `membership_id`, `role_id`, `organization_id`, or the
-- scope columns (it can never repoint one), and no DELETE. The strongest true
-- statement is that the data plane may REVOKE a membership's direct role grants and
-- may do nothing else.
GRANT SELECT ON org_membership_roles TO ironauth_app;
GRANT UPDATE (updated_at, deleted_at) ON org_membership_roles TO ironauth_app;
