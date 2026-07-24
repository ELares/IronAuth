-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Organization group members (issue #97, milestone M10).
--
-- Creates `org_group_members`: the join row binding one ORG MEMBERSHIP into one
-- GROUP of the same organization. This is the first hop of effective-role
-- resolution and therefore sits on the token-issuance path.
--
--   1. The subject column is `membership_id` (an omb_ id), NOT a bare user id.
--      That is the whole containment argument for this table: group membership
--      PRESUPPOSES organization membership structurally, so "a user in a group of
--      an organization they do not belong to" is not merely refused by the
--      repository, it is not expressible. The price is that a membership's
--      lifecycle now reaches these rows, which migration 0089 and the repository
--      pay in full: removing a membership CASCADES a soft delete over its group
--      memberships and its direct role assignments, so a removed and re-added
--      user comes back with no groups and no roles. An org_memberships row is
--      REVIVED rather than recreated on a re-add (it keeps its id), so without
--      that cascade a re-added user would silently regain every group and every
--      role they held when they were removed. Removing someone from an
--      organization is a security operation and must not be quietly reversible in
--      its authorization effects.
--   2. `organization_id` is DENORMALIZED from the group and the membership, which
--      already agree on it. It is not a convenience: row-level security fences
--      (tenant, environment) and NOTHING finer, so the organization predicate that
--      every read and every write repeats is the only thing keeping one
--      organization's rows out of a sibling organization's queries inside one
--      environment. Carrying the column lets every statement fence the
--      organization without a join.
--   3. The table is NOT capped. There is no count constraint, no quota check, and
--      no advisory-lock-plus-COUNT gate anywhere: a project covenant forbids any
--      cap or paywall gate on how many members a group may hold or how many
--      groups a member may belong to. Both are unlimited.
--
-- The delta vocabulary (issue #97, and what milestone M11 will consume). Every
-- mutation of this table writes an audit_log row in the SAME transaction as the
-- mutation, through the store's single audited-write path, under one of two
-- actions: `organization.group.member.add` and
-- `organization.group.member.remove`. The membership cascade described above
-- additionally writes `organization.membership.attachments.revoke` against the
-- MEMBERSHIP, carrying an operator-safe count of what it stripped, because the
-- rows it soft-deletes are not individually addressed by the request that caused
-- them to disappear and the history is otherwise unreconstructable. Those action
-- strings ARE the delta contract for a group membership. There is deliberately NO
-- outbox table and no change feed here: IronAuth has no eventing delivery surface
-- yet (that is M11), and migration 0025 records why a shared outbox built without
-- a concrete consumer in view is very likely the wrong shape. Delivery is
-- deferred, not stubbed. ADR 0002 is binding: who is in a group is always its
-- rows, never a fold over events.
--
-- Migration safety obligation (see migrate.rs): `org_group_members` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH
-- CHECK, carries the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Grants are least-privilege and COLUMN-scoped for the
-- UPDATE (the #31 lesson). Every statement is additive (a new table, its indexes,
-- its policy, and its grants; no existing column is altered or dropped), so this
-- migration is an EXPAND.

CREATE TABLE org_group_members (
    -- The gmb_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The organization both endpoints belong to. Denormalized deliberately (see
    -- the header): every read and every write repeats it as a predicate, because
    -- the row-level-security policy does not fence organizations.
    organization_id text        NOT NULL,
    -- The group the membership is bound into (a grp_ id of this organization).
    group_id        text        NOT NULL,
    -- The organization membership bound into the group (an omb_ id of this
    -- organization), never a bare user id. See the header for why.
    membership_id   text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the binding was removed (present only in a soft-deleted row). The row
    -- is retained so the audit foreign key to it stays satisfiable.
    deleted_at      timestamptz,
    CONSTRAINT org_group_members_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Each endpoint's id is globally unique and embeds its own scope, so id-only
    -- foreign keys are sufficient and are the backstop that makes a binding to a
    -- nonexistent or cross-scope group, membership, or organization impossible
    -- (the 0084 precedent). SAME-ORGANIZATION containment between the three is an
    -- APPLICATION invariant the repository resolves explicitly before every write.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    FOREIGN KEY (group_id) REFERENCES org_groups (id),
    FOREIGN KEY (membership_id) REFERENCES org_memberships (id)
);

-- At most one LIVE binding per (group, membership). The index is PARTIAL over live
-- rows, so removing a member frees the pair immediately and re-adding inserts a
-- FRESH row with a FRESH id rather than tripping a permanent conflict; every read
-- filters deleted_at IS NULL, so the reads and this uniqueness invariant agree on
-- exactly the live set. A removed binding is never REVIVED, so the audit history
-- of a removal is never overwritten by the row that replaces it.
CREATE UNIQUE INDEX org_group_members_group_membership_live_uniq
    ON org_group_members (tenant_id, environment_id, group_id, membership_id)
    WHERE deleted_at IS NULL;

-- "Who is in this group", on the stable (created_at, id) pagination key.
CREATE INDEX org_group_members_group_idx
    ON org_group_members (tenant_id, environment_id, group_id, created_at, id);

-- "Which groups is this membership in": the SEED of effective-role resolution, so
-- this index is on the token-issuance hot path and is the one index in this
-- migration whose absence would be a latency defect rather than a scan.
CREATE INDEX org_group_members_membership_idx
    ON org_group_members (tenant_id, environment_id, membership_id, created_at, id);

ALTER TABLE org_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY org_group_members_tenant_isolation ON org_group_members
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
-- The CONTROL plane owns the admin membership-in-group surface: list and inspect
-- (SELECT), add (INSERT), and remove through a COLUMN-scoped UPDATE of EXACTLY the
-- soft-delete pair. Nothing else is granted: `group_id`, `membership_id`,
-- `organization_id`, the scope columns, and `id` are all ABSENT from the UPDATE
-- list, so an existing binding can never be REPOINTED at a different group, a
-- different member, a different organization, or a different scope. That is what
-- makes "this row's containment was checked when it was written" a durable
-- statement rather than a statement about one instant: there is no UPDATE that can
-- undo the check afterwards. DELETE is granted to nobody on either plane: removal
-- is the soft delete.
GRANT SELECT, INSERT ON org_group_members TO ironauth_control;
GRANT UPDATE (updated_at, deleted_at) ON org_group_members TO ironauth_control;

-- The DATA plane needs SELECT, because effective-role resolution SEEDS its ancestor
-- walk from this table on the token-issuance path, which runs under the
-- low-privilege app role. The SELECT is granted HERE, in the creating migration,
-- rather than being deferred to the PR that first needs it: the 0027-then-0084
-- revoke-and-re-grant churn on `organizations` is the cautionary precedent for
-- deferring a grant the design already knows it needs.
GRANT SELECT ON org_group_members TO ironauth_app;

-- The data plane additionally needs the COLUMN-scoped soft-delete pair, and ONLY
-- that pair, for exactly one reason: the invitation-accept side effect runs on this
-- plane (which is why 0084 grants the same shape on `org_memberships`), and
-- accepting an invitation REVIVES a previously removed membership, keeping its
-- original id. A revived membership must come back holding no groups, so the accept
-- transaction has to be able to revoke this table's rows. Without this grant the
-- accept path would fail with SQLSTATE 42501, and the only ways to make it succeed
-- again would be to drop the cascade on that path (the silent hole where a removed
-- user restores every group by redeeming an old invitation) or to move the accept
-- side effect to the control plane (a much larger change to a data-plane flow).
--
-- What the data plane still CANNOT do is the whole point of the column scoping: no
-- INSERT, so it can never create a binding; no UPDATE on `group_id`,
-- `membership_id`, `organization_id`, or the scope columns, so it can never repoint
-- one; no DELETE, so removal stays a soft delete. The strongest true statement is
-- therefore that the data plane may REVOKE a membership's group bindings and may do
-- nothing else, which is strictly narrower than what it already holds on the
-- `org_memberships` row those bindings hang off.
GRANT UPDATE (updated_at, deleted_at) ON org_group_members TO ironauth_app;
