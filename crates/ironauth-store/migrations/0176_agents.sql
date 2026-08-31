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
    -- The agt_ scoped identifier; embeds its (tenant, environment).
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

    CONSTRAINT agents_state_closed
        CHECK (state IN ('active', 'suspended', 'revoked')),
    -- 64 tools is far above anything an agent legitimately declares and far below anything
    -- that makes a token unwieldy. A bound in the schema is one no handler can forget.
    CONSTRAINT agents_tool_scopes_bounded
        CHECK (array_length(tool_scopes, 1) IS NULL OR array_length(tool_scopes, 1) <= 64),
    CONSTRAINT agents_display_name_bounded
        CHECK (char_length(display_name) BETWEEN 1 AND 200)
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
    'Issue #130: active | suspended | revoked. A suspended agent obtains no tokens and stays '
    'listable and auditable, which a soft delete could not express.';
COMMENT ON COLUMN agents.tool_scopes IS
    'Issue #130: the DECLARED tool set. A request for anything outside it is refused and the '
    'denial audited; the set lives here rather than in a token so an agent cannot widen it.';
