-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Client-credentials service-account principals and per-client custom claims
-- (issue #23).
--
-- The client-credentials grant (RFC 6749 4.4) mints machine-to-machine access
-- tokens. Every M2M-capable client maps to a first-class SERVICE-ACCOUNT
-- PRINCIPAL with a stable, per-(tenant, environment) subject identifier that is
-- DISTINCT from the client id and consistent across every issuance (RFC 9068:
-- `sub` = the principal, `client_id` = the client). This migration lands:
--
--   1. A clients composite UNIQUE (id, tenant_id, environment_id), so the
--      service_accounts table below can carry an ISOLATION-PRESERVING composite
--      foreign key to it (a principal can only bind a client in its OWN tenant and
--      environment). id is already the PRIMARY KEY, so the tuple is trivially
--      unique; this constraint exists solely to anchor the composite FK, exactly
--      as grants (0004) exposes UNIQUE (id, tenant_id, environment_id) for its
--      children.
--   2. service_accounts: the (client -> principal) mapping. The principal id is a
--      `sva_` scoped identifier minted lazily on the client's FIRST
--      client-credentials issuance; the row is the stable `sub` returned every
--      time after. One principal per client (UNIQUE), so `sub` never diverges. The
--      row is the first-class principal RBAC (M10) will attach roles/permissions
--      to; this issue only stores the identity.
--   3. A clients ALTER (additive) for the per-client STATIC custom-claims config
--      (`custom_token_claims`, a JSON object). Declarative claims embedded in the
--      client's M2M tokens; a custom claim can never override a protected
--      registered claim (that guard lives in the mint, ironauth-oidc).
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. service_accounts does all four. The clients ALTERs are
-- additive (a new UNIQUE over the existing PK columns, and a nullable column),
-- safe for the old binary to ignore.

-- ---------------------------------------------------------------------------
-- 1. Anchor the isolation-preserving composite FK on clients.
ALTER TABLE clients
    ADD CONSTRAINT clients_scope_identity_unique UNIQUE (id, tenant_id, environment_id);

-- ---------------------------------------------------------------------------
-- 2. The service-account principal: the stable machine `sub` (issue #23).
--
-- id is the `sva_` scoped principal identifier (embeds its (tenant, environment)).
-- client_id is the `cli_` client the principal belongs to, UNIQUE per environment
-- so a client resolves to EXACTLY ONE principal (its `sub` is therefore stable and
-- consistent across issuances). The isolation-preserving composite FK ties the
-- principal to a client in the SAME tenant and environment, so a principal can
-- never bind a client of another scope.
CREATE TABLE service_accounts (
    -- The sva_ scoped principal identifier; embeds its (tenant, environment).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The OAuth client this principal is the service account for. One principal
    -- per client, so a client's `sub` is stable across every issuance.
    client_id      text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_accounts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One principal per client per environment: the client selects the principal,
    -- so the mapping must be unambiguous (and its `sub` stable).
    UNIQUE (tenant_id, environment_id, client_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the client must exist in the SAME
    -- tenant and environment.
    FOREIGN KEY (client_id, tenant_id, environment_id)
        REFERENCES clients (id, tenant_id, environment_id)
);

CREATE INDEX service_accounts_scope_idx
    ON service_accounts (tenant_id, environment_id);

ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_accounts_tenant_isolation ON service_accounts
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to resolve the stable principal, INSERT to mint it lazily at first
-- issuance. No UPDATE or DELETE: a principal, once minted, is stable forever (its
-- id IS the `sub`); rotating it would break every token that carries it.
GRANT SELECT, INSERT ON service_accounts TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. Per-client static custom claims (issue #23). Additive nullable JSONB column,
-- safe for the old binary: NULL (the default) means no custom claims, today's
-- behavior. When set, it is a JSON OBJECT whose members are embedded verbatim into
-- the client's client-credentials access tokens. A custom claim can NEVER override
-- a protected registered claim (iss/sub/aud/exp/iat/jti/client_id/scope): that
-- guard is enforced in the mint (ironauth-oidc), and the setter validates the
-- shape. The app role already holds table-wide UPDATE on clients (0001), so no new
-- grant is needed.
ALTER TABLE clients ADD COLUMN custom_token_claims jsonb;
