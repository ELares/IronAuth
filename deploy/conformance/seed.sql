-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Deterministic seed for the OIDF conformance harness (issue #37). This is a
-- SEED SCRIPT, not a schema migration: it inserts fixed rows the suite needs to
-- drive scripted, headless login and consent. It never alters the schema.
--
-- It runs as the Postgres SUPERUSER (the container's `ironauth` role), which
-- bypasses row-level security, so it can insert scoped rows directly. seed.sh
-- renders __USER_PASSWORD_HASH__ (an Argon2id PHC string it computes for the
-- committed cert password) and pipes the result to psql. Everything is a
-- throwaway cert-only value.
--
-- Scope: tenant "cert" and environment "cert", so the per-environment issuer is
-- exactly https://op/t/cert/e/cert (matching ironauth.toml's public_url).

BEGIN;

-- Level 1: operator (the platform deployment itself; not tenant-scoped).
INSERT INTO operators (id, display_name)
VALUES ('op-cert', 'Conformance Operator')
ON CONFLICT (id) DO NOTHING;

-- Level 2: tenant.
INSERT INTO tenants (id, operator_id, display_name)
VALUES ('cert', 'op-cert', 'Conformance Tenant')
ON CONFLICT (id) DO NOTHING;

-- Level 3: environment. The (id, tenant_id) pair is what scoped rows reference.
INSERT INTO environments (id, tenant_id, display_name)
VALUES ('cert', 'cert', 'Conformance Environment')
ON CONFLICT (id) DO NOTHING;

-- The deterministic end-user the suite logs in as. identifier is the login
-- handle; password_hash is an Argon2id PHC verifier (seed.sh renders it from the
-- committed cert password documented in that script). One account per handle per
-- scope, so re-seeding is idempotent.
INSERT INTO users (id, tenant_id, environment_id, identifier, password_hash)
VALUES (
    'user-cert-alice',
    'cert',
    'cert',
    'alice@conformance.test',
    '__USER_PASSWORD_HASH__'
)
ON CONFLICT (tenant_id, environment_id, identifier) DO NOTHING;

-- Clients: the certified profiles register their OWN clients through Dynamic
-- Client Registration (ironauth.toml sets registration_enabled = true,
-- registration_mode = "open"), so no static relying party is required for the
-- Basic / Config / Dynamic / Form Post profiles. If an owner chooses to run a
-- profile WITHOUT DCR, add a static client below. It is left commented because
-- the clients table gains columns across migrations; validate the column set
-- against the current schema (crates/ironauth-store/migrations) before enabling
-- it. redirect_uris must exactly match the suite's callback for the run.
--
-- INSERT INTO clients (
--     id, tenant_id, environment_id, display_name,
--     token_endpoint_auth_method, secret_hash, redirect_uris
-- )
-- VALUES (
--     'client-cert-rp', 'cert', 'cert', 'Conformance Seed RP',
--     'client_secret_basic',
--     '__CLIENT_SECRET_HASH__',
--     ARRAY['https://localhost.emobix.co.uk:8443/test/a/ironauth/callback']
-- )
-- ON CONFLICT (id) DO NOTHING;

COMMIT;
