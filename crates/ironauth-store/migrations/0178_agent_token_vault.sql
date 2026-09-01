-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The agent token vault (issue #132): downstream third-party credentials an agent acts with.
--
-- This table makes IronAuth the CUSTODIAN of somebody else's credential, which is a different
-- kind of row from everything else here. A leaked user record is bad; a leaked Google refresh
-- token is an attacker acting as that user inside Google, on a credential IronAuth cannot
-- revoke. So the token material is SEALED with the same per-tenant key hierarchy that seals
-- PII, and the acceptance criterion is stated as a property of a raw dump: it yields no
-- usable third-party credential. Nothing here stores a token in a readable column.

CREATE TABLE agent_vault_connections (
    -- The `avc_` scoped identifier; embeds its (tenant, environment).
    id                      text        PRIMARY KEY,
    tenant_id               text        NOT NULL,
    environment_id          text        NOT NULL,
    -- The agent this connection belongs to. Per-AGENT, not per-user: two agents acting for
    -- the same person hold separate connections, so revoking one cannot silently keep the
    -- other's downstream reach alive.
    agent_id                text        NOT NULL,
    -- The downstream provider, a closed set. An open column would let a caller invent a
    -- provider name and store a credential nothing knows how to refresh or revoke.
    provider                text        NOT NULL,
    -- SEALED. Never a readable column, ever: see the header.
    access_token_sealed     bytea       NOT NULL,
    access_token_dek_version integer    NOT NULL,
    -- The refresh token, when the provider issued one. Sealed under its own purpose so a
    -- ciphertext moved between the two columns fails to open rather than opening as the
    -- other secret.
    refresh_token_sealed    bytea,
    refresh_token_dek_version integer,
    -- What the downstream provider actually granted, which is not always what was asked for.
    granted_scopes          text[]      NOT NULL DEFAULT ARRAY[]::text[],
    expires_at              timestamptz,
    -- `active` or `failed`. A connection whose refresh stopped working is marked rather than
    -- deleted, so ONE broken connection is visible and isolated instead of taking an agent's
    -- other connections down with it (criterion 3).
    state                   text        NOT NULL DEFAULT 'active',
    -- Why it failed, for the operator. Never the provider's response verbatim: an upstream
    -- body can carry a token.
    last_error              text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_vault_connections_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT agent_vault_connections_provider_closed
        CHECK (provider IN ('google', 'github')),
    CONSTRAINT agent_vault_connections_state_closed
        CHECK (state IN ('active', 'failed')),
    -- The refresh token and its key version travel together or not at all: a sealed value
    -- with no version cannot be opened, and a version with no value describes nothing.
    CONSTRAINT agent_vault_connections_refresh_paired
        CHECK ((refresh_token_sealed IS NULL) = (refresh_token_dek_version IS NULL)),
    CONSTRAINT agent_vault_connections_last_error_bounded
        CHECK (last_error IS NULL OR char_length(last_error) <= 500),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The agent must exist. Without this a connection could outlive the principal it belongs
    -- to, which is a third-party credential with no owner to revoke it through.
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);

-- One connection per agent per provider. Two would make "which credential is this agent's
-- Google one" ambiguous, and the exchange resolves exactly that question.
CREATE UNIQUE INDEX agent_vault_connections_agent_provider
    ON agent_vault_connections (tenant_id, environment_id, agent_id, provider);

ALTER TABLE agent_vault_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_vault_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_vault_connections_scope ON agent_vault_connections
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The control plane writes connections; the data plane READS them at exchange time and
-- updates state on a refresh. It may not create one: a connection is established through an
-- operator-driven flow, never as a side effect of a token request.
GRANT SELECT, INSERT, UPDATE ON agent_vault_connections TO ironauth_control;
GRANT SELECT, UPDATE ON agent_vault_connections TO ironauth_app;

COMMENT ON COLUMN agent_vault_connections.access_token_sealed IS
    'Issue #132: the downstream access token, sealed with the per-tenant key hierarchy. A raw '
    'dump of this column yields no usable third-party credential, which is the criterion.';
COMMENT ON COLUMN agent_vault_connections.state IS
    'Issue #132: active | failed. A failed connection is marked rather than deleted so one '
    'broken downstream is visible and ISOLATED from the same agent other connections.';
