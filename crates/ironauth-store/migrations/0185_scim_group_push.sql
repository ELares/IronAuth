-- SCIM group push: the data plane may create and populate an organization group (issue #135).
--
-- WHAT THIS CHANGES, SAID PLAINLY.
--
-- 0087 says of `org_groups`: "No data-plane path ever writes a group, so INSERT, UPDATE, and
-- DELETE are granted to nobody there." 0088 says of `org_group_members` that the data plane
-- "may REVOKE a membership's group bindings and may do nothing else". Both sentences were true
-- when they were written and both are SUPERSEDED here. SCIM group push is the first data-plane
-- path that writes a group, and this migration is what makes it possible. Those two migrations
-- are checksummed and cannot be corrected in place, so this is where the correction lives.
--
-- WHY THIS IS THE RIGHT PLANE FOR IT.
--
-- The SCIM surface is public: its callers are Okta, Entra and their peers, which are hosted
-- services on the open internet, so it runs on the public plane under `ironauth_app` like
-- every other public surface. Group push therefore has to be a data-plane write or not exist.
--
-- The alternative considered was a dedicated `ironauth_scim` role holding exactly these grants
-- and nothing else, which is strictly better least-privilege and is the right shape if this
-- surface ever needs a privilege the rest of the public plane must not have. It is not that
-- yet, and the reason is the comparison below: what this grants is SMALLER than what the data
-- plane already holds.
--
-- WHAT THIS ACTUALLY WIDENS, AND WHAT IT DOES NOT.
--
-- The data plane already holds `SELECT, INSERT` on `org_memberships` (0084, for the
-- invitation-accept path). Binding a person into an organization is a STRICTLY larger
-- privilege than putting a person who is already in that organization into one of its groups:
-- the membership is what makes them a principal there at all, and every group binding hangs
-- off a membership that already exists.
--
-- A group binding confers roles only through `org_group_roles`, and this migration grants the
-- data plane NOTHING on that table. So the strongest true statement about what a compromised
-- data-plane path gains here is: it may CREATE a group, RENAME one, SOFT-DELETE one, and put
-- existing members of an organization into groups of that organization. It may NOT attach a
-- role to a group, so it cannot manufacture a privilege an operator has not already attached
-- to some group.
--
-- The soft-delete half is named explicitly because it is the sharpest of the four and the
-- easiest to miss: `deleted_at` is in the UPDATE list below, and `ActingOrgGroupRepo::delete`
-- is an UPDATE of exactly that column, so `DELETE /scim/v2/Groups/{id}` works and REMOVES
-- every role its group conferred. That is a real reduction in privilege a compromised
-- data-plane path can cause, and it is the price of serving RFC 7644 section 3.6 on this
-- plane. It cannot GRANT anything, which is the property that matters.
--
-- The column scoping keeps the 0087/0088 containment property intact. `organization_id`,
-- `parent_id`, `slug`, `group_id`, `membership_id` and the scope columns are all ABSENT from
-- every UPDATE list below, so a row whose containment was checked when it was written can
-- never be repointed afterwards. The SQL DELETE verb is still granted to nobody -- removal is
-- the soft delete named above, so a removed group stays auditable.

-- `org_groups`: create, rename and soft-delete. `slug` is deliberately NOT in the UPDATE list, so the
-- stable name a token claim carries stays immutable exactly as 0087 made it, and a SCIM
-- rename moves the label only. `parent_id` is likewise absent: this surface creates flat
-- groups, and a data-plane path that could reparent one could graft a group under a
-- role-bearing ancestor and inherit its roles.
--
-- `metadata` IS in the list, and not because this surface sets it. `ActingOrgGroupRepo::update`
-- is one statement shared with the control plane and its SET list always names `metadata`
-- (`COALESCE($2::jsonb, metadata)`, so a NULL argument leaves the value alone). Postgres checks
-- the column privilege for every column a SET list names, unchanged value or not, so without
-- this grant every rename fails with SQLSTATE 42501 -- which is what happened, and is why this
-- line is here rather than a shorter list that looks tighter and does not work. The column
-- carries no authorization: nothing derives a role, a permission or a claim from it.
GRANT INSERT ON org_groups TO ironauth_app;
GRANT UPDATE (display_name, metadata, updated_at, deleted_at) ON org_groups TO ironauth_app;

-- `org_group_members`: create a binding. The soft-delete pair was already granted by 0088 for
-- the invitation-accept cascade, so removal needs nothing new; only INSERT is added.
GRANT INSERT ON org_group_members TO ironauth_app;

-- The scope policies 0087 and 0088 installed are PERMISSIVE and already cover the app role's
-- INSERT and UPDATE: each has a WITH CHECK requiring the row's scope columns to equal the
-- session's, so a data-plane write outside the caller's scope is refused by the policy exactly
-- as a control-plane one is. Nothing is added here, and nothing needs to be: a new policy
-- would be a SECOND answer to a question 0087 and 0088 already answer, and two policies on one
-- table are OR'd, so a permissive addition could only ever widen what they allow.

-- ---------------------------------------------------------------------------------------
-- WHETHER AN ORGANIZATION CONSIDERS A PERSON ACTIVE (issue #135).
--
-- WHY THIS TABLE EXISTS AT ALL.
--
-- SCIM's `active` is per RESOURCE, and a SCIM resource is a person AS THIS ORGANIZATION SEES
-- THEM. IronAuth has two nearby things and neither is that:
--
--   * `users.state` is the person in the whole ENVIRONMENT. Mapping `active` onto it lets a
--     credential for organization B stop a shared person signing in to organization A -- a
--     cross-organization write through a door that never names organization A. That is not
--     hypothetical: it is what the first version of this surface did, and a reviewer drove it
--     with one DELETE.
--   * `org_memberships.state` is the right SHAPE but its CHECK is a closed set of exactly
--     ('active'), so there is no value meaning "a member this organization has deactivated",
--     and widening that set would arm every existing reader that assumes a live membership is
--     an active one.
--
-- WHY NOT JUST REMOVE THE MEMBERSHIP.
--
-- Because REACTIVATION has to work. Deactivate-then-reactivate is the second most common thing
-- a provisioning client does after create (a rehire, or a sync blip), and it reactivates BY
-- RESOURCE ID. If deactivating removed the membership the person would no longer be visible to
-- the credential, the reactivating PATCH would answer the uniform 404, and the identity
-- provider would be stuck with no way to undo its own deactivation. So deactivating leaves the
-- membership in place and writes here instead, and the person stays addressable.
--
-- DELETE is a different act and keeps its own meaning: RFC 7644 section 3.6 deletes the
-- resource, so it removes the membership and the person genuinely stops being visible.
--
-- A client that wants them back POSTs them again, and THAT WORKS BECAUSE OF THIS TABLE. The
-- account row, the login identifier and this connection's `externalId` mapping all survive a
-- delete (0184 grants no DELETE there, deliberately), so without something recording that this
-- organization once held the person, the re-POST would collide with all three and every route
-- back would be closed -- which is what a reviewer found before this table existed: an Okta
-- rehire was unrecoverable through SCIM.
--
-- A `false` row here is that record, and it is exactly the right key for it: only the SCIM
-- surface writes this table, only for the organization on the credential, and only when that
-- organization deactivated or deleted the person.
--
-- BOTH halves are required. A create naming somebody with a `false` row AND no membership in
-- this organization is a RE-ADMIT; a create naming somebody this organization still HOLDS is
-- the ordinary conflict even when their row says false, because a deactivated member is a live
-- resource that a client reactivates with `active: true` rather than re-creates. A create
-- naming anybody else -- including another organization's live user -- is likewise a conflict. Conditioning the re-admit on "not currently a member"
-- instead would be true of every user in the environment and would let any credential take
-- another organization's user by naming their handle.
--
-- SCOPED TO THE ORGANIZATION, NOT THE CONNECTION. Two connections provisioning one
-- organization must agree about who is active in it: a per-connection answer would let one
-- identity provider report a person active while another reported them not, and nothing could
-- say which the organization meant.
CREATE TABLE IF NOT EXISTS scim_membership_activation (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    organization_id text        NOT NULL,
    user_id         text        NOT NULL,
    -- FALSE means this organization has deactivated the person. There is no row for the
    -- ordinary case, so an absent row reads as active and provisioning a person writes
    -- nothing here.
    active          boolean     NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, organization_id, user_id),
    CONSTRAINT scim_membership_activation_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE scim_membership_activation ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_membership_activation FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_membership_activation_scope ON scim_membership_activation
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns this table outright: SCIM is the only thing that writes it and the only
-- thing that reads it. UPDATE is column-scoped to the two mutable columns, so the row's
-- subject -- which organization, which person, which scope -- can never be repointed, exactly
-- as 0087 and 0088 fence theirs. DELETE is granted to nobody: reactivating writes `true`
-- rather than removing the row, so the fact that this organization once deactivated somebody
-- is not erased by their coming back.
GRANT SELECT, INSERT ON scim_membership_activation TO ironauth_app;
GRANT UPDATE (active, updated_at) ON scim_membership_activation TO ironauth_app;

-- The CONTROL plane reads, so the operator-facing question "who has this organization
-- deactivated" has an answer. No caller yet; see the same note on 0184's control grant.
GRANT SELECT ON scim_membership_activation TO ironauth_control;

COMMENT ON TABLE scim_membership_activation IS
    'Issue #135: whether ONE organization considers a person active, which is what SCIM''s '
    '`active` means. Absent row = active. Deliberately not users.state (environment wide, so '
    'one organization could disable a person for another) and not org_memberships.state '
    '(closed CHECK set with no deactivated value).';
