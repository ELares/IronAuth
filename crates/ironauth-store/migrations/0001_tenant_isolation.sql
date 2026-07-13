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
-- The server connects as this role: NEVER a superuser and NEVER a table owner,
-- so FORCE ROW LEVEL SECURITY on the scoped tables always applies to it (a
-- superuser bypasses row-level security entirely, and a table owner bypasses it
-- without FORCE).
--
-- This migration does NOT create the role and NEVER sets a password. The role is
-- provisioned out of band -- in production by the operator (credential management
-- is owned by the migration framework, #7), and in tests by the integration
-- harness (crates/ironauth-store/src/test_support.rs), which creates it
-- race-safely with a throwaway credential before applying this schema. Shipping a
-- CREATE ROLE ... PASSWORD literal in a public repository would hand every reader
-- a working credential for the isolation-boundary role -- and that role can
-- itself bind the scope session variables, so knowing its password defeats
-- row-level security for every tenant. Provisioning is therefore always
-- deliberate, never defaulted. If the role is absent when this runs, the GRANTs
-- below fail loudly: that fail-closed behavior is intended.
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
    -- Deny-by-default depends on no scoped row ever carrying an empty scope (see
    -- the row-level-security note below): a warmed pooled connection compares
    -- against the empty string, not NULL. Make that an enforced invariant.
    CONSTRAINT organizations_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
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
    -- See organizations above: an empty scope must never reach a row, so that a
    -- warmed connection's empty-string scope variable can never match.
    CONSTRAINT clients_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
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
-- with set_config(.., true).
--
-- Deny by default holds regardless of connection state. On a PRISTINE connection
-- the variable was never set, current_setting(.., true) returns NULL, and
-- `tenant_id = NULL` is never true. On a POOLED connection that already ran a
-- scoped transaction, set_config(.., true) has reverted the variable to the
-- EMPTY STRING (not NULL) at commit, so the check becomes `tenant_id = ''`.
-- Either way the session sees nothing, because the CHECK constraints above forbid
-- any scoped row from carrying an empty tenant_id or environment_id. Deny by
-- default is thus an enforced invariant, not an accident of NULL semantics.

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
