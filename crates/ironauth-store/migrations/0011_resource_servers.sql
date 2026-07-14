-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Resource-server registry (issue #29).
--
-- A resource server is a registered protected API that OAuth access tokens are
-- minted FOR. Each registration binds an `audience` (the resource identifier /
-- resource URI a token targets) to the access-token `token_format` that resource
-- server receives (an RFC 9068 `at+jwt` or an opaque, digest-only token) and an
-- optional per-resource-server access-token lifetime. When a token exchange
-- carries a resource/audience that matches a registered audience, the mint emits
-- that resource server's format and lifetime; otherwise it uses the environment
-- default (a config setting). The RFC 8707 `resource` REQUEST-parameter wiring
-- that feeds the audience from the token request is issue #28; this table is the
-- persistence the selection reads.
--
-- Tenant-scoped and isolated exactly like `clients` and the OIDC grant tables:
-- mandatory tenant_id and environment_id, the nonempty-scope CHECK, forced
-- row-level security keyed on the same transaction-local session variables, the
-- same isolation-preserving foreign keys, and reachable only through the
-- data-plane scoped repository (ironauth_app). The `audience` is unique per
-- environment, so a resource identifier selects at most one format.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh.
-- resource_servers does all four.

CREATE TABLE resource_servers (
    -- The rsv_ scoped identifier; embeds its (tenant, environment).
    id                    text        PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- The resource-server identifier / resource URI a token targets. Unique per
    -- environment, so a matched audience selects exactly one format.
    audience              text        NOT NULL,
    -- The access-token format this resource server receives: 'at_jwt' (an RFC
    -- 9068 signed JWT) or 'opaque' (a random, digest-only reference token).
    token_format          text        NOT NULL,
    -- The per-resource-server access-token lifetime in seconds; NULL falls back
    -- to the environment default lifetime.
    access_token_ttl_secs bigint,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT resource_servers_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The two shipped formats; a new format is a deliberate schema change.
    CONSTRAINT resource_servers_token_format_valid
        CHECK (token_format IN ('at_jwt', 'opaque')),
    -- A non-negative, non-zero lifetime when present (a zero-second token is born
    -- expired); NULL is the fall-back-to-environment-default sentinel.
    CONSTRAINT resource_servers_ttl_positive
        CHECK (access_token_ttl_secs IS NULL OR access_token_ttl_secs > 0),
    -- One registration per audience per environment: the audience selects the
    -- format, so it must be unambiguous.
    UNIQUE (tenant_id, environment_id, audience),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX resource_servers_scope_idx
    ON resource_servers (tenant_id, environment_id);

ALTER TABLE resource_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_servers_tenant_isolation ON resource_servers
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT: a resource server is registered once and read at mint time. No
-- UPDATE or DELETE path ships here (re-registration to change a format is a later
-- milestone); a column-scoped UPDATE grant would be added only if update lands.
GRANT SELECT, INSERT ON resource_servers TO ironauth_app;
