-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Out-of-band approval for a sensitive agent action (issue #132, criterion 4).
--
-- The shape of the criterion decides the shape of the table: a sensitive action BLOCKS until
-- somebody approves it, and denial or timeout issues no tokens. "Blocks" therefore cannot be
-- a process holding a request open, because the approver is a human on another device and
-- the wait is unbounded. It is a DURABLE row the requester polls, which is also what makes
-- criterion 5 hold without any messaging backbone: a pending approval is a row, so it
-- survives a delivery worker restart because there is nothing in flight to lose.
--
-- The approved authorization_details (RFC 9396) are rendered ON DECISION and stored here.
-- They are what the approver actually agreed to, which is not always what was asked for: an
-- approver who narrows a request must have the narrowed set be the one that takes effect, or
-- the approval surface is decorative.

CREATE TABLE agent_vault_approvals (
    -- The `ava_` scoped identifier; embeds its (tenant, environment).
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The agent that asked. Scoped by agent so an approval for one agent can never be
    -- consumed by another, which is the same per-agent fence the vault read applies.
    agent_id            text        NOT NULL,
    -- The downstream provider the action targets.
    provider            text        NOT NULL,
    -- What was REQUESTED, as RFC 9396 authorization_details. Stored verbatim so the approver
    -- is shown the request rather than a summary of it.
    requested_details   jsonb       NOT NULL,
    -- What was APPROVED. NULL until decided, and NOT necessarily equal to the request: an
    -- approver may narrow it, and the narrowed set is the one that takes effect.
    approved_details    jsonb,
    -- pending | approved | denied | expired. A closed set: an unknown state would be a
    -- request nothing can decide and nothing can time out.
    state               text        NOT NULL DEFAULT 'pending',
    -- When the request stops being answerable. A pending approval with no deadline is an
    -- action that blocks for ever, which is the failure mode "denial OR TIMEOUT issues no
    -- tokens" exists to rule out.
    expires_at          timestamptz NOT NULL,
    decided_at          timestamptz,
    -- Who decided. Recorded because an approval nobody is accountable for is not an approval.
    decided_by          text,
    created_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_vault_approvals_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT agent_vault_approvals_state_closed
        CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    -- A decided approval names when and by whom; a pending one names neither. Without this
    -- a row could claim to be approved with no decision behind it.
    CONSTRAINT agent_vault_approvals_decision_paired
        CHECK (
            (state = 'pending' AND decided_at IS NULL AND decided_by IS NULL)
            OR (state <> 'pending' AND decided_at IS NOT NULL)
        ),
    -- Only an APPROVED row carries approved details. A denied or expired row carrying them
    -- would be a set somebody could mistake for a grant.
    CONSTRAINT agent_vault_approvals_details_only_when_approved
        CHECK ((approved_details IS NULL) OR (state = 'approved')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);

-- The approver's queue: what is still waiting, oldest first.
CREATE INDEX agent_vault_approvals_pending
    ON agent_vault_approvals (tenant_id, environment_id, state, created_at);

ALTER TABLE agent_vault_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_vault_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_vault_approvals_scope ON agent_vault_approvals
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The control plane decides; the data plane raises a request and reads its own answer. It
-- may not decide: an agent approving its own sensitive action is the whole thing this
-- prevents.
GRANT SELECT, INSERT, UPDATE ON agent_vault_approvals TO ironauth_control;
GRANT SELECT, INSERT ON agent_vault_approvals TO ironauth_app;

COMMENT ON COLUMN agent_vault_approvals.approved_details IS
    'Issue #132: what the approver AGREED to, which may be narrower than the request. NULL '
    'until decided, and only ever present on an approved row.';
COMMENT ON COLUMN agent_vault_approvals.expires_at IS
    'Issue #132: when the request stops being answerable. A pending approval with no deadline '
    'blocks for ever, which is what "denial or timeout issues no tokens" rules out.';
