-- 0176: agent identities as FIRST-CLASS PRINCIPALS (issue #130).
--
-- An agent is not a user with a funny name and not a service account with a label. It acts
-- FOR someone, inside an organization, with a declared and bounded set of tools. Every one of
-- those three is a column here rather than a convention, because each is something an
-- authorization decision reads:
--
--   * `organization_id` is the boundary. Criterion 4 asks that agents be environment-scoped
--     AND organization-linked, so an org admin listing "all agents acting for my organization"
--     is answering a question the schema can answer rather than filtering a global list.
--   * `linked_user_id` is the accountability. An agent acting for nobody is an unattributable
--     principal, which is precisely what this issue exists to prevent: criterion 2 asks that
--     every event be attributable to the agent AND its linked user AND its organization.
--   * `tool_scopes` is the bound. Criterion 3 asks that a request outside the declared set be
--     rejected with an audited denial, and a declared set that lived in a token would be one
--     the agent could ask to widen.
--
-- STATE, not a boolean. Criterion 5 asks that a SUSPENDED agent cannot obtain tokens but
-- REMAINS listable and auditable, which a `deleted_at` cannot express: a soft delete hides the
-- row from the very list an investigator needs. `revoked` is the terminal one.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it
-- inert.

CREATE TABLE agents (
    -- The agp_ scoped identifier; embeds its (tenant, environment).
    id               text        PRIMARY KEY,
    tenant_id        text        NOT NULL,
    environment_id   text        NOT NULL,
    -- The organization this agent acts inside (an org_ id in this scope).
    organization_id  text        NOT NULL,
    -- The user this agent acts FOR (a usr_ id in this scope). NOT NULL by design: see above.
    linked_user_id   text        NOT NULL,
    -- The operator-facing label. Never an authorization input.
    display_name     text        NOT NULL,
    -- The lifecycle state. A closed set, checked below.
    state            text        NOT NULL DEFAULT 'active',
    -- The DECLARED tool scopes. Bounded, because an unbounded set is an unbounded token.
    tool_scopes      text[]      NOT NULL DEFAULT ARRAY[]::text[],
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    -- The scope columns are never empty. `error::is_absent_scope` converts a write into a
    -- nonexistent scope to the uniform not-found by matching the scope foreign key's
    -- 23503; without these keys there is no 23503, nothing converts, and the row LANDS
    -- as an orphan under a scope that does not exist, then is hidden from every scope
    -- that does by the policy below. Every sibling scoped table carries this pair.
    CONSTRAINT agents_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT agents_state_closed
        CHECK (state IN ('active', 'suspended', 'revoked')),
    -- 64 tools is far above anything an agent legitimately declares and far below anything
    -- that makes a token unwieldy. A bound in the schema is one no handler can forget.
    CONSTRAINT agents_tool_scopes_bounded
        CHECK (array_length(tool_scopes, 1) IS NULL OR array_length(tool_scopes, 1) <= 64),
    CONSTRAINT agents_display_name_bounded
        CHECK (char_length(display_name) BETWEEN 1 AND 200),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization the agent acts inside must exist. Organization ids are globally
    -- unique, so an id-only key is sufficient, exactly as `org_memberships` does it.
    -- This is the backstop that makes an agent in a nonexistent or cross-scope
    -- organization impossible even though the handler resolves the org up front.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    -- The user the agent acts FOR must exist. Users are soft-deleted, so an agent is
    -- never hard-deleted out from under a scope, and the linkage an investigator
    -- follows cannot dangle.
    FOREIGN KEY (linked_user_id) REFERENCES users (id)
);

-- The listing criterion 1 asks for: every agent acting for one organization, oldest first.
CREATE INDEX agents_by_org
    ON agents (tenant_id, environment_id, organization_id, created_at, id);

-- And the reverse question an investigator asks: what is acting for this person.
CREATE INDEX agents_by_linked_user
    ON agents (tenant_id, environment_id, linked_user_id);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;

CREATE POLICY agents_scope ON agents
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle. A data plane that could register an agent and then
-- mint for it would be a privilege escalation with no operator in the loop, and one that could
-- widen `tool_scopes` would be an agent granting itself tools.
GRANT SELECT, INSERT, UPDATE ON agents TO ironauth_control;

-- The DATA plane READS, because token issuance has to check the state and the declared tools
-- on every request. It may not write: see above.
GRANT SELECT ON agents TO ironauth_app;

COMMENT ON COLUMN agents.state IS
    'Issue #130: active | suspended | revoked. Suspension is the reversible control and '
    'revocation is terminal; both stay listable and auditable, which a soft delete could '
    'not express. Blocking issuance for a non-active agent is the follow-up half.';
COMMENT ON COLUMN agents.tool_scopes IS
    'Issue #130: the DECLARED tool set, recorded here rather than in a token so an agent '
    'cannot widen it. Checking a request against it, and auditing the denial, is the '
    'follow-up half; this column is the declaration, not yet the control.';
