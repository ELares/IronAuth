-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- FedCM assertion nonce replay store: the fedcm_assertion_nonces table (issue #83).
--
-- The IdP-side FedCM id-assertion endpoint (issue #83, EXPLORATORY) mints an ID
-- token directly to the requesting RP. The credentialed-cookie, Sec-Fetch-Dest, and
-- registered-origin gates already block a web-attacker replay, but the issue
-- explicitly requires rejecting a REPLAYED nonce server-side as defense in depth. A
-- single-use latch on the RP-supplied (client_id, nonce) delivers that: the first
-- assertion for a nonce CONSUMES it, and a second identical (client_id, nonce) within
-- the TTL is refused as a replay.
--
-- There is no reusable nonce/replay table today: the OIDC `nonce` is only a
-- passthrough column on authorization_codes (never a replay store), and every other
-- single-use table is keyed by its OWN token id, not an arbitrary RP-supplied nonce.
--
--   fedcm_assertion_nonces: one row per consumed (or reserved) FedCM assertion nonce.
--     - a scope embedded `fdn_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - client_id: the `cli_` RP the assertion was issued to. The single-use key is
--       (tenant, environment, client_id, nonce): a nonce is scoped to the RP that
--       supplied it, exactly as the assertion binds `aud = client_id`;
--     - nonce: the RP-supplied assertion nonce, an opaque short-lived value. It is
--       NOT a secret and NOT personal data (an RP-chosen anti-replay token), so it is
--       stored as plaintext text, exactly like the authorization_codes `nonce`
--       passthrough column;
--     - expires_at: the single-use TTL boundary. The consume guard admits a row only
--       while unexpired, so a stale nonce past its TTL is simply not resolvable and a
--       retention sweep can prune expired rows;
--     - consumed_at: the single-use latch (the house consumed_at idiom, mirroring
--       authorization_codes 0004). A consumed row is the durable replay evidence, so
--       there is NO DELETE grant: a consumed row is never removed by the data plane;
--     - created_at: the creation instant (the database clock DEFAULT, a non secret
--       audit timestamp).
--
--     Runtime data (issue #41): a FedCM assertion nonce is dynamic per-environment
--     single-use anti-replay state (like an authorization_code or an email_otp_code),
--     NEVER promotable config, so it STRUCTURALLY never enters a config snapshot (only
--     Promotable types are exported). Like the other single-use token tables it carries
--     no first-class ResourceType variant.
--
-- The UNIQUE (tenant, environment, client_id, nonce) constraint is the STRUCTURAL
-- single-use invariant: a given RP nonce exists at most once in a scope, so the
-- guarded insert either wins (first use) or collides (replay). The repository's
-- consume method runs the guarded write, so exactly one concurrent request wins.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant scoped table ENABLES
-- and FORCES row level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The FedCM assertion nonce single-use replay store (issue #83).
CREATE TABLE fedcm_assertion_nonces (
    -- The fdn_ scoped identifier; embeds its (tenant, environment).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The `cli_` RP the assertion nonce is scoped to (the assertion's audience).
    client_id      text        NOT NULL,
    -- The RP-supplied anti-replay nonce. Not a secret and not personal data; stored
    -- as plaintext exactly like the authorization_codes nonce passthrough column.
    nonce          text        NOT NULL,
    -- The single-use TTL boundary: the consume guard admits a row only while unexpired.
    expires_at     timestamptz NOT NULL,
    -- The single-use latch: NULL until the first assertion consumes the nonce. A
    -- consumed row is the durable replay evidence, so the table has no DELETE grant.
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fedcm_assertion_nonces_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The STRUCTURAL single-use invariant: an RP nonce exists at most once in a scope.
    CONSTRAINT fedcm_assertion_nonces_uniq
        UNIQUE (tenant_id, environment_id, client_id, nonce),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- Prune expired nonces on a retention sweep (the TTL boundary is the sweep key).
CREATE INDEX fedcm_assertion_nonces_expiry_idx
    ON fedcm_assertion_nonces (tenant_id, environment_id, expires_at);

ALTER TABLE fedcm_assertion_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE fedcm_assertion_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY fedcm_assertion_nonces_tenant_isolation ON fedcm_assertion_nonces
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane RESERVES a nonce (INSERT) and CONSUMES it (UPDATE consumed_at). There
-- is NO DELETE grant: a consumed row is the durable replay evidence and is never
-- removed by the data plane (a retention sweep runs as the owner role, like the other
-- single-use token tables).
GRANT SELECT, INSERT, UPDATE ON fedcm_assertion_nonces TO ironauth_app;
