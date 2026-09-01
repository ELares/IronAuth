-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Bind an agent to the OAuth client it obtains tokens through (issue #130).
--
-- The agent principal (0176) is the WHO. This is the door it comes through. Issue #130
-- is explicit that issuance must use standard grants rather than a proprietary path, so
-- an agent gets its tokens the way every other machine identity does: as the service
-- account of an OAuth client, through `client_credentials`. What this column adds is the
-- reverse lookup the issuance path needs -- given the client at the door, WHICH agent is
-- this, and what did it declare it may ask for.
--
-- NULLABLE, because an agent is registered before it has a client and stays useful
-- without one: it is listable, auditable, and revocable from the moment it exists. An
-- agent with no client simply obtains no tokens, which is the same answer a suspended one
-- gets and needs no special case at the door.
ALTER TABLE agents
    ADD COLUMN client_id text;

-- One agent per client per environment. The issuance path resolves the agent FROM the
-- client, so two agents behind one client would make that lookup ambiguous and the
-- attribution this whole issue exists for unprovable. Partial, because NULL is the
-- ordinary state of an agent that has not been bound yet and many of those coexist.
CREATE UNIQUE INDEX agents_client_unique
    ON agents (tenant_id, environment_id, client_id)
    WHERE client_id IS NOT NULL;

-- The isolation-preserving composite reference `service_accounts` uses, and for the same
-- reason: an agent must never bind a client of another scope. The scope columns are in
-- the key, so a cross-scope client id cannot satisfy it even if a caller supplies one.
ALTER TABLE agents
    ADD CONSTRAINT agents_client_scope_fkey
    FOREIGN KEY (client_id, tenant_id, environment_id)
        REFERENCES clients (id, tenant_id, environment_id);

-- The issuance lookup: given the client at the door, resolve the agent. Covered by the
-- unique index above for the equality probe, so this is only the scope-ordered scan the
-- admin listing already has; no second index is added.

COMMENT ON COLUMN agents.client_id IS
    'Issue #130: the OAuth client this agent obtains tokens through, or NULL before it is '
    'bound. The issuance path resolves the agent FROM this client, which is why it is '
    'unique per environment.';
