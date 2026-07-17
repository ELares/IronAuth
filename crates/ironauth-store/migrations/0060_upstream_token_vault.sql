-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Enterprise inbound federation: the upstream token vault (issue #77, PR 3).
--
-- After a brokered login, the upstream access and refresh tokens can optionally be
-- persisted so an authorized downstream client can call the upstream API on the
-- user's behalf (the Keycloak Identity Brokering V2 shape). The capture is GATED
-- per org connection (capture_upstream_tokens) and per connector (refresh
-- capability); a plain social login persists nothing. This migration lands the two
-- tables that machinery reads and writes.
--
--   upstream_tokens: one row per (session, connector). It holds the captured
--     upstream tokens SEALED under the per-tenant envelope (issue #48), so a
--     database dump carries only ciphertext. It holds:
--       - a scope embedded `utk_` id (embeds its (tenant, environment), so a row
--         minted in one scope parses as a uniform not found under another);
--       - session_id: the session the tokens were captured for. This is the IDOR
--         scoping key: a retrieval reads the row BY the caller's OWN session id, and
--         the FK is ON DELETE CASCADE so the tokens share the session's lifetime
--         (deleting or ending the session destroys its captured tokens);
--       - connector_id: the `cnr_` connector describing the upstream;
--       - access_token_sealed / refresh_token_sealed: the envelope ciphertext of the
--         upstream tokens (bytea), sealed under pii_dek_version with an AAD bound to
--         the session and the token kind, so an access-token ciphertext can never be
--         opened as a refresh token nor lifted to another session's row. The refresh
--         column is NULLABLE (the upstream may issue no refresh token);
--       - pii_dek_version: the DEK version that sealed the two columns;
--       - access_expires_at / token_scope: NON-secret metadata (when the access token
--         expires, and the granted upstream OAuth scope). The tenant/environment
--         SCOPE nonempty CHECK below is unrelated to the token_scope column.
--     Classified ResourceType::Runtime (issue #41): dynamic per-environment data
--     that NEVER enters a config snapshot (only Promotable types are exported).
--
--   upstream_token_grants: the authorization config for WHICH client may retrieve a
--     session's upstream tokens. One row per (client, org_connection). It holds NO
--     secret, so it is classified Promotable and travels in a config snapshot. A
--     retrieval requires a matching enabled grant, else a typed unauthorized_client
--     denial.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant scoped table ENABLES
-- and FORCES row level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per session upstream token vault (issue #77, PR 3).
CREATE TABLE upstream_tokens (
    -- The utk_ scoped identifier; embeds its (tenant, environment).
    id                    text        PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- The session the tokens were captured for (the IDOR scoping key). ON DELETE
    -- CASCADE from sessions gives the vault the session's lifetime: ending or
    -- deleting the session destroys its captured tokens.
    session_id            text        NOT NULL,
    -- The connector describing the upstream (a cnr_ id).
    connector_id          text        NOT NULL,
    -- The upstream tokens, envelope-encrypted at rest (issue #48): only ciphertext
    -- ever lands here. The refresh ciphertext is NULLABLE (the upstream may issue no
    -- refresh token). The seal AAD binds each to the session and the token kind.
    access_token_sealed   bytea       NOT NULL,
    refresh_token_sealed  bytea,
    -- The DEK version that sealed the two columns above.
    pii_dek_version       integer     NOT NULL,
    -- NON-secret metadata: when the access token expires (from the clock seam at
    -- capture), and the granted upstream OAuth scope.
    access_expires_at     timestamptz,
    token_scope           text        NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT upstream_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- At most one captured token row per (session, connector) in a scope.
    CONSTRAINT upstream_tokens_session_connector_uniq
        UNIQUE (tenant_id, environment_id, session_id, connector_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The session-scoped lifetime: deleting the session CASCADE-deletes its tokens.
    FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
);

-- The retrieval reads the row by the caller's OWN session id.
CREATE INDEX upstream_tokens_session_idx
    ON upstream_tokens (tenant_id, environment_id, session_id);

ALTER TABLE upstream_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY upstream_tokens_tenant_isolation ON upstream_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane CAPTURES the tokens after a brokered login and READS them for an
-- authorized retrieval. The vault is Runtime (never exported), so the control plane
-- has no grant on it. The session-cascade delete runs as a referential action, which
-- is not subject to a caller grant.
GRANT SELECT, INSERT ON upstream_tokens TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The per client upstream-token retrieval grant (issue #77, PR 3).
CREATE TABLE upstream_token_grants (
    -- The utg_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The client authorized to retrieve upstream tokens (a cli_ id).
    client_id         text        NOT NULL,
    -- The org connection whose sessions' tokens this client may retrieve (an ocn_ id).
    org_connection_id text        NOT NULL,
    -- Whether the grant is active (a revoke switch).
    enabled           boolean     NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT upstream_token_grants_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- At most one grant per (client, org connection) in a scope.
    CONSTRAINT upstream_token_grants_client_org_uniq
        UNIQUE (tenant_id, environment_id, client_id, org_connection_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The management list and the config snapshot export read a scope's grants ordered by
-- the stable (created_at, id) key.
CREATE INDEX upstream_token_grants_scope_idx
    ON upstream_token_grants (tenant_id, environment_id, created_at, id);

ALTER TABLE upstream_token_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_token_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY upstream_token_grants_tenant_isolation ON upstream_token_grants
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane reads a grant to authorize a retrieval; the CONTROL plane owns the
-- lifecycle (create) and reads for the snapshot export. No secret column exists.
GRANT SELECT ON upstream_token_grants TO ironauth_app;
GRANT SELECT, INSERT ON upstream_token_grants TO ironauth_control;
