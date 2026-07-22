-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per environment, per client admin consent pre authorizations (issue #88, PR 4).
--
-- A third party (not first_party) client must be admin pre authorized for its requested scope
-- before it can obtain user consent at the authorization endpoint. An admin pre authorization
-- covering the requested scope SKIPS the user consent screen (the Microsoft model: the admin
-- grant is the consent of record); an uncovered third party request is refused with a "requires
-- administrator approval" terminal (there is no user self consent). This table stores those
-- pre authorizations as RUNTIME per environment state:
--
--   client_admin_grants: one row per (tenant, environment, client). It holds:
--     - a scope embedded `cag_` id (embeds its (tenant, environment), so a row minted in one
--       scope parses as a uniform not found under another);
--     - client_id: the authorize client id this pre authorization governs, the stable per
--       environment natural key within scope. Unique per (tenant, environment);
--     - granted_scope: the space separated OAuth scope set the admin pre authorized (nullable;
--       NULL pre authorizes only the empty scope, the secure floor). A request is admitted only
--       when its requested scope is a SUBSET of this set;
--     - granted_by: the opaque actor id string of the admin that recorded the pre authorization
--       (an audit convenience column, not a secret and not PII);
--     - created_at / updated_at: the write instants from the application clock seam.
--
-- Distinct from clients.first_party (0076): first_party is a boolean identity carve out (a first
-- party client is exempt from the gate wholesale); client_admin_grants is the granular per scope
-- escape for a third party client. This pre authorization is RUNTIME, NOT promotable (issue #41):
-- it is never carried in a config snapshot, so a promoted third party client is LOCKED in the
-- target environment until a target environment admin pre authorizes it (secure by default per
-- environment, consistent with user consents, which are never promoted).
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and FORCES
-- row level security, adds the (tenant, environment) isolation policy, adds the nonempty scope
-- CHECK, and is registered in scripts/query-audit.sh. Every statement is additive, so this
-- migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment, per client admin consent pre authorization store (issue #88, PR 4).
CREATE TABLE client_admin_grants (
    -- The cag_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The authorize client id this pre authorization governs: the stable per environment natural
    -- key. Unique per (tenant, environment).
    client_id          text        NOT NULL,
    -- The space separated OAuth scope set the admin pre authorized (nullable). A request is
    -- admitted only when its requested scope is a SUBSET of this set; NULL pre authorizes only
    -- the empty scope.
    granted_scope      text,
    -- The opaque actor id string of the admin that recorded the pre authorization.
    granted_by         text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT client_admin_grants_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '' AND client_id <> '' AND granted_by <> ''),
    -- A stored granted_scope, when present, is never the empty string (an empty pre authorization
    -- is expressed as NULL, so the covers check never has to distinguish "" from NULL).
    CONSTRAINT client_admin_grants_granted_scope_nonempty
        CHECK (granted_scope IS NULL OR granted_scope <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A client id is unique per (tenant, environment): one admin pre authorization per (scope,
-- client), so a repeat write overwrites in place and reuses the row id.
CREATE UNIQUE INDEX client_admin_grants_client_idx
    ON client_admin_grants (tenant_id, environment_id, client_id);

ALTER TABLE client_admin_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_admin_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY client_admin_grants_tenant_isolation ON client_admin_grants
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS the pre authorization lifecycle: set (create /
-- overwrite), get, and delete a client's admin consent pre authorization.
GRANT SELECT, INSERT, UPDATE, DELETE ON client_admin_grants TO ironauth_control;
-- The DATA plane READS the active pre authorization on the authorization consent gate path, so
-- it holds SELECT only (a compromised or buggy data plane path can never self author a
-- pre authorization and defeat the gate).
GRANT SELECT ON client_admin_grants TO ironauth_app;
