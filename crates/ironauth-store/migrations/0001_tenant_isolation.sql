-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Tenant and environment isolation at the persistence layer (issue #6).
--
-- This is the ROOT schema decision for the four-level resource model
-- (operator > tenant > environment > organization) and the deny-by-default
-- (tenant, environment) filter. It is deliberately MINIMAL: the full
-- expand-contract migration framework and the same-transaction audit log are
-- owned by the relational primary store (issue #7). Only what tenant isolation
-- needs ships here.
--
-- Isolation is enforced in three layers, below the application:
--   1. typed scoped identifiers (Rust) that embed tenant and environment;
--   2. scope-only repositories (Rust) that apply the filter to every query;
--   3. Postgres row-level security (this file), FORCED, as defense in depth.

-- ---------------------------------------------------------------------------
-- Low-privilege application role.
--
-- The server connects as this role in production. It is NEVER a superuser and
-- NEVER a table owner, so FORCE ROW LEVEL SECURITY on the scoped tables always
-- applies to it (a superuser would bypass row-level security entirely, and a
-- table owner would bypass it without FORCE). The idempotent guard exists
-- because roles are cluster-global and shared across the fresh per-test
-- databases the integration harness creates.
--
-- The bootstrap password here is for the embedded test cluster only; a
-- production deployment provisions this role's credentials out of band (the
-- migration framework, #7, owns credential management).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ironauth_app') THEN
        CREATE ROLE ironauth_app LOGIN PASSWORD 'ironauth_app';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Level 1: operator. The platform deployment itself. Not tenant-scoped.
CREATE TABLE operators (
    id           text        PRIMARY KEY,
    display_name text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Level 2: tenant. A customer of the operator.
CREATE TABLE tenants (
    id           text        PRIMARY KEY,
    operator_id  text        NOT NULL REFERENCES operators (id),
    display_name text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Level 3: environment. For example prod or staging, within a tenant.
-- The UNIQUE (id, tenant_id) lets scoped tables reference the pair, so an
-- environment can never be paired with the wrong tenant.
CREATE TABLE environments (
    id           text        PRIMARY KEY,
    tenant_id    text        NOT NULL REFERENCES tenants (id),
    display_name text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);

-- Level 4: organization. SCHEMA SLOT ONLY in milestone M1 (see
-- docs/design/TENANCY.md). Organizations become a public API resource in M5 and
-- the full B2B surface in M10; here the table exists purely so scoped tables and
-- the isolation harness cover it from day one. It is a tenant-scoped table:
-- mandatory tenant_id and environment_id, and row-level security below.
CREATE TABLE organizations (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    display_name   text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- Worked example of a tenant-scoped resource: an OAuth client. Every scoped
-- table carries mandatory tenant_id and environment_id from day one; this is
-- the deny-by-default filter made a column, not a convention.
CREATE TABLE clients (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    display_name   text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX clients_scope_idx ON clients (tenant_id, environment_id);
CREATE INDEX organizations_scope_idx ON organizations (tenant_id, environment_id);

-- ---------------------------------------------------------------------------
-- Row-level security on every tenant-scoped table.
--
-- ENABLE turns the policies on; FORCE makes them apply even to the table owner,
-- so isolation does not depend on which role happens to own the table. The
-- policy keys on the transaction-local session variables the repository binds
-- with set_config(.., true). current_setting(.., true) returns NULL when the
-- variable is unset, and `column = NULL` is never true, so a session that
-- forgot to set its scope sees NOTHING: deny by default.

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients FORCE ROW LEVEL SECURITY;
CREATE POLICY clients_tenant_isolation ON clients
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant_isolation ON organizations
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The application role gets data-plane rights on the scoped tables and nothing
-- more. It cannot read the operator, tenant, or environment level tables (those
-- are the management plane's, issue #11); it cannot alter policies; it is
-- subject to row-level security on every row it can touch.
GRANT SELECT, INSERT, UPDATE, DELETE ON clients TO ironauth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations TO ironauth_app;
