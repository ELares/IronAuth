-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- What a stored connection needs in order to REFRESH itself (issue #132, criterion 3).
--
-- Criterion 3 is "stored-token refresh works and a failing connection isolates without
-- affecting other connections". The isolation half shipped with 0178: a broken connection is
-- MARKED rather than deleted, so one dead downstream is visible and does not take an agent's
-- other connections with it. The refresh half did not, and could not: refreshing an OAuth
-- credential means presenting the stored refresh token at the PROVIDER's token endpoint with
-- the client credentials that provider issued, and none of those three things had anywhere to
-- live. The vault stored a refresh token nothing could spend.
--
-- ON THE CONNECTION, not in a per-provider config table. The tempting shape is one row per
-- provider per environment, and it is wrong here for a reason worth writing down: two agents
-- in the same environment can legitimately hold connections issued to DIFFERENT downstream
-- OAuth clients, because the downstream client is chosen by whoever ran the consent flow, not
-- by IronAuth. A per-provider table would force them to share one, and the first agent whose
-- credential was minted by a different client would silently fail to refresh.
--
-- ALL THREE NULLABLE, and null means "this connection cannot refresh". That is a fact about
-- the connection rather than missing data: a credential established through a flow that
-- returned no refresh token, or one an operator stored by hand, simply has to be re-established
-- when it expires. The exchange says so distinctly rather than reporting it as a failure.
--
-- The client SECRET is sealed exactly as the two token columns are, under its own purpose tag,
-- so it cannot be opened as an access token or a refresh token and neither can be opened as it.
-- It is the third secret in this table and it gets the same treatment as the first two: there
-- is no window in which it sits readable.

ALTER TABLE agent_vault_connections
    ADD COLUMN refresh_token_endpoint text,
    ADD COLUMN refresh_client_id text,
    ADD COLUMN refresh_client_secret_sealed bytea,
    ADD COLUMN refresh_client_secret_dek_version integer;

-- The four travel together or not at all. A partially configured refresh is a refresh that
-- fails at the provider rather than at the edge, which turns an operator's incomplete input
-- into a downstream error nobody can act on.
ALTER TABLE agent_vault_connections
    ADD CONSTRAINT agent_vault_connections_refresh_config_paired
    CHECK (
        (refresh_token_endpoint IS NULL
         AND refresh_client_id IS NULL
         AND refresh_client_secret_sealed IS NULL
         AND refresh_client_secret_dek_version IS NULL)
        OR
        (refresh_token_endpoint IS NOT NULL
         AND refresh_client_id IS NOT NULL
         AND refresh_client_secret_sealed IS NOT NULL
         AND refresh_client_secret_dek_version IS NOT NULL)
    );

-- https only, checked here rather than only at the edge. This URL is dereferenced by the
-- server with a refresh token in the body: a plaintext one puts the credential on the wire.
-- The bound is generous against any real endpoint and small against a hostile one.
ALTER TABLE agent_vault_connections
    ADD CONSTRAINT agent_vault_connections_refresh_endpoint_https
    CHECK (
        refresh_token_endpoint IS NULL
        OR (refresh_token_endpoint LIKE 'https://%' AND char_length(refresh_token_endpoint) <= 2048)
    );

COMMENT ON COLUMN agent_vault_connections.refresh_token_endpoint IS
    'Issue #132: the provider token endpoint the stored refresh token is spent at. NULL means '
    'this connection cannot refresh and must be re-established when it expires.';
COMMENT ON COLUMN agent_vault_connections.refresh_client_secret_sealed IS
    'Issue #132: the downstream client secret, sealed under its own purpose tag so it cannot '
    'be opened as an access or refresh token, and neither can be opened as it.';

-- ---------------------------------------------------------------------------
-- Which connections are SENSITIVE, and which ACTION an approval is for
-- (issue #132, criterion 4).
--
-- Two columns for one defect, found by review: the approval gate restrained only a
-- COOPERATIVE agent.
--
-- The gate ran when the exchange request named `authorization_details`, so the agent chose
-- whether to enter it. A denied agent re-sent the same exchange with the field omitted and got
-- the identical credential. "Denial issues no tokens" was true of the gate's interior and
-- false of the endpoint. `requires_approval` moves that decision to the OPERATOR, where it
-- belongs: they establish the connection, they say whether reaching it is sensitive, and the
-- agent cannot opt out of the answer. Default false, so every connection stored before this
-- behaves exactly as it did.
--
-- And an approval was keyed on (agent, provider) alone, so approving one action authorized
-- EVERY action at that provider for the rest of the window: approve a payment of one, then
-- exchange for a payment of a million against the same approval. The approver's narrowing
-- changed a response field and nothing else, which is what 0179 calls "decorative". The digest
-- binds an approval to the exact request it was raised for. A different action finds no
-- approval and raises its own, which also means a denial of one action stops being a denial of
-- everything the agent might ever do at that provider.
--
-- A DIGEST rather than the details themselves: the comparison is equality, the details can be
-- large, and an index on a jsonb column to answer "is there an approval for exactly this" is a
-- worse tool than an index on 64 hex characters.

ALTER TABLE agent_vault_connections
    ADD COLUMN requires_approval boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN agent_vault_connections.requires_approval IS
    'Issue #132: whether exchanging for this credential is a sensitive action that blocks on '
    'an out-of-band approval. Set by the OPERATOR at store time, never by the agent: an agent '
    'that could decide this could decline to.';

ALTER TABLE agent_vault_approvals
    ADD COLUMN action_digest text;

-- Backfilled to the empty string rather than left NULL, so the lookup predicate is a plain
-- equality on every row. No row exists yet -- 0179 shipped in the same release as this -- but
-- writing the backfill rather than assuming an empty table is what makes this safe if that
-- ever stops being true.
UPDATE agent_vault_approvals SET action_digest = '' WHERE action_digest IS NULL;

ALTER TABLE agent_vault_approvals
    ALTER COLUMN action_digest SET NOT NULL;

-- NOT NULL with a DEFAULT, and the default is what makes the rollout safe. Migrations run
-- before the new binary is everywhere, so for a window the OLD binary is still inserting
-- approvals without this column; NOT NULL and no default turns that window into "no approval
-- can be raised at all", which fails an agent's sensitive exchange for a reason no operator
-- can see. An empty digest matches no lookup -- the reader's digest is always 64 hex
-- characters -- so a row raised in that window is invisible to the gate rather than a pass:
-- the agent asks again on the new binary, a properly bound request is raised, and the stray
-- row times out.
ALTER TABLE agent_vault_approvals
    ALTER COLUMN action_digest SET DEFAULT '';

ALTER TABLE agent_vault_approvals
    ADD CONSTRAINT agent_vault_approvals_action_digest_shaped
    CHECK (action_digest ~ '^[0-9a-f]{64}$' OR action_digest = '');

-- The lookup the exchange performs: the newest approval for exactly this action.
CREATE INDEX agent_vault_approvals_action_idx
    ON agent_vault_approvals
       (tenant_id, environment_id, agent_id, provider, action_digest, created_at DESC);

-- ONE pending approval per (agent, provider, action). Two concurrent sensitive exchanges both
-- read "no approval" and both insert, and the exchange then polls the newer of the two; an
-- approver who decides the older one has decided a row nothing reads, and the agent waits for
-- a decision that already happened. A unique index makes the second insert lose instead, and
-- the loser re-reads the winner.
--
-- PARTIAL on `state = 'pending'`, because a decided approval is history: an agent that was
-- approved, expired, and asks again must be able to raise a new request for the same action,
-- and a unique index over every state would refuse it forever.
CREATE UNIQUE INDEX agent_vault_approvals_one_pending_per_action
    ON agent_vault_approvals (tenant_id, environment_id, agent_id, provider, action_digest)
    WHERE state = 'pending';

-- ---------------------------------------------------------------------------
-- An approval is SPENT when the credential it authorized is handed over
-- (issue #132, criterion 4).
--
-- Found by review. An approved row authorized every exchange of that action for the whole
-- window: one human decision on "pay 1 GBP" let the agent take the credential fifty times in
-- the next hour. The approval is a decision about AN ACTION, so it authorizes an action, not
-- an hour of them.
--
-- 'consumed' rather than a `consumed_at` column plus a state, because the two would be a pair
-- that can disagree, and `agent_vault_approvals_decision_paired` already ties every non-pending
-- state to a decision timestamp. A consumed row keeps its `decided_at` and `decided_by`: the
-- human still decided it, and losing who approved what at the moment it is spent would be
-- exactly backwards.
--
-- The gate answers a consumed row by raising a NEW request, which the pending-uniqueness index
-- permits because it is partial on `state = 'pending'`. So an agent that legitimately needs the
-- action twice asks twice, and a human answers twice.
ALTER TABLE agent_vault_approvals
    DROP CONSTRAINT agent_vault_approvals_state_closed;

ALTER TABLE agent_vault_approvals
    ADD CONSTRAINT agent_vault_approvals_state_closed
    CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'consumed'));

COMMENT ON COLUMN agent_vault_approvals.state IS
    'pending | approved | denied | expired | consumed. A closed set: an unknown state would be '
    'a request nothing can decide and nothing can time out. `consumed` means the credential it '
    'authorized has been handed over, so it authorizes nothing further (issue #132).';
