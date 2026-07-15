-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Environment-scoped secrets and variables (issue #45).
--
-- The config-promotion flagship needs one canonical snapshot to apply to every
-- environment with environment-specific values injected at apply time (the
-- PingOne AIC "environment secrets and variables" pattern, built in natively).
-- This migration lays the per-(tenant, environment) store those references
-- resolve against:
--
--   1. environment_variables: NON-SECRET, named configuration values (endpoints,
--      feature toggles, display strings). A variable is PROMOTABLE (issue #41): its
--      name AND value travel in a config snapshot (issue #43), so the value column
--      is plaintext and readable through the API. One value per (scope, name).
--
--   2. environment_secrets: SENSITIVE, named values (connector credentials,
--      webhook signing keys). A secret is WRITE-ONLY through the API (a read
--      returns metadata only: name, version, updated_at, never the value) and is
--      ENVIRONMENT-IDENTITY (issue #41): the VALUE never travels between
--      environments; only a NAMED REFERENCE to it does, resolved per target
--      environment. The value is sealed under the scope's envelope
--      data-encryption key (issue #48, the same DEK/KEK/AEAD substrate that seals
--      the bootstrap users PII columns): the ciphertext lives on this table as a
--      `bytea` column (nonce || ciphertext || tag), with the tenant, environment,
--      secret name, and DEK version bound as associated data so a ciphertext
--      cannot be replayed across a row, tenant, environment, secret, or key
--      version. There is NO plaintext column, so a database dump yields no secret.
--
-- Both are TENANT-SCOPED tables in the sense every scoped table is: a mandatory
-- (tenant_id, environment_id), the nonempty-scope CHECK, forced row-level
-- security keyed on the transaction-local session variables the scoped repository
-- binds, the isolation-preserving foreign keys, and reachable only through the
-- scoped repository (registered in scripts/query-audit.sh). A secret or variable
-- in environment A is therefore invisible to environment B, by construction and
-- below the application layer.
--
-- Grants follow the #31 least-privilege lesson (never a table-wide UPDATE that
-- silently covers a future column). The DATA-plane role (ironauth_app) manages
-- both resources (it is the role that holds the envelope master key and the
-- encrypted_secrets/DEK grants, so it is the plane that seals and opens a secret
-- value). The CONTROL-plane role (ironauth_control) additionally reads
-- environment_variables so the management-plane snapshot export (issue #43, which
-- runs the promotable-resource read as ironauth_control) can carry a variable's
-- value; it is NOT granted any read of environment_secrets, so a secret value can
-- never be reached through the export path even in principle.
--
-- Expand-only and safe for the old binary: two new CREATE TABLEs plus their
-- indexes, policies, and grants. A binary that predates this migration never
-- reads or writes these tables; a binary that postdates it provisions a scope's
-- KEK/DEK lazily on the first secret write (issue #48), exactly as the users PII
-- path does.

-- ---------------------------------------------------------------------------
-- Non-secret, promotable environment variables (name -> value).
CREATE TABLE environment_variables (
    -- The var_ scoped identifier (embeds its (tenant, environment)).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The variable name, unique per scope: the stable key a snapshot reference
    -- resolves against and the natural key the export orders by.
    name           text        NOT NULL,
    -- The plaintext configuration value. NON-secret by classification: a variable
    -- is promotable, so its value is readable and travels in a snapshot.
    value          text        NOT NULL,
    -- Monotonic write version, bumped on every overwrite (metadata for the API).
    version        integer     NOT NULL DEFAULT 1,
    -- Creation and last-write instants, from the application clock seam.
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT environment_variables_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One value per (scope, name).
    UNIQUE (tenant_id, environment_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX environment_variables_scope_idx
    ON environment_variables (tenant_id, environment_id);

ALTER TABLE environment_variables ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_variables FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_variables_tenant_isolation ON environment_variables
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Data-plane management: SELECT/INSERT/DELETE plus a COLUMN-SCOPED UPDATE over
-- exactly the columns an overwrite rewrites (the value, its version, and the
-- update instant). Never a table-wide UPDATE (the #31 lesson).
GRANT SELECT, INSERT, DELETE ON environment_variables TO ironauth_app;
GRANT UPDATE (value, version, updated_at) ON environment_variables TO ironauth_app;
-- Control-plane read for the snapshot export (issue #43): a variable is
-- promotable, so the management-plane export must read its name and value. SELECT
-- only; the control role never writes a variable.
GRANT SELECT ON environment_variables TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Sensitive, write-only environment secrets (name -> sealed value).
CREATE TABLE environment_secrets (
    -- The esec_ scoped identifier (embeds its (tenant, environment)).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The secret name, unique per scope: the stable key a snapshot reference
    -- resolves against. The name is metadata (not sensitive); the VALUE is sealed.
    name           text        NOT NULL,
    -- Which DEK version sealed the ciphertext (issue #48). Bound into the seal AAD
    -- and used to pick the right DEK on read; a rotation's background re-encryption
    -- would advance it.
    dek_version    integer     NOT NULL,
    -- The secret value sealed under the scope's DEK (nonce || ciphertext || tag).
    -- This is the ONLY payload column, and it is NEVER plaintext: a database dump
    -- of this column yields ciphertext bound to (tenant, environment, name,
    -- dek_version), unreadable without the scope's key hierarchy.
    ciphertext     bytea       NOT NULL,
    -- Monotonic write version, bumped on every overwrite (metadata a read returns).
    version        integer     NOT NULL DEFAULT 1,
    -- Creation and last-write instants, from the application clock seam.
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT environment_secrets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One value per (scope, name).
    UNIQUE (tenant_id, environment_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX environment_secrets_scope_idx
    ON environment_secrets (tenant_id, environment_id);

ALTER TABLE environment_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_secrets_tenant_isolation ON environment_secrets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Data-plane management: SELECT/INSERT/DELETE plus a COLUMN-SCOPED UPDATE over
-- exactly the columns an overwrite rewrites (the sealed value, its DEK version,
-- the write version, and the update instant). Never a table-wide UPDATE (#31).
-- The control role is granted NOTHING here: a secret value is never reachable
-- through the control-plane export path.
GRANT SELECT, INSERT, DELETE ON environment_secrets TO ironauth_app;
GRANT UPDATE (ciphertext, dek_version, version, updated_at) ON environment_secrets TO ironauth_app;
