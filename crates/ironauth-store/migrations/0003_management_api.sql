-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Management API control plane (issue #11).
--
-- This migration adds everything the OpenAPI-first management API needs at the
-- persistence layer, in one expand-phase change:
--
--   1. A SECOND low-privilege role, ironauth_control, distinct from the
--      data-plane ironauth_app. Management mutations touch the operator, tenant,
--      and environment LEVEL tables that ironauth_app deliberately cannot; the
--      control role gets exactly those rights (and append-only audit rights) and
--      nothing on the data-plane scoped tables. "Control-plane credentials are a
--      distinct class from data-plane keys" is made real here at the DB layer.
--   2. A soft-delete column on tenants and environments. Hard-deleting either is
--      structurally impossible while the append-only audit_log holds a foreign
--      key to them (an audit row can never be removed), so DELETE is a soft
--      deactivation that keeps the row and its referential integrity intact.
--   3. management_credentials: environment-scoped management API keys (mak_),
--      a tenant-scoped table with forced row-level security exactly like clients.
--   4. idempotency_keys: the Idempotency-Key replay store, keyed by the acting
--      CREDENTIAL (see the note on it below for why it is credential-scoped, not
--      tenant-RLS-scoped).
--
-- Migration safety obligation (see migrate.rs): a new tenant-scoped table must,
-- in the same migration, ENABLE and FORCE row-level security, add the
-- (tenant, environment) isolation policy, add the nonempty-scope CHECK, and be
-- registered in scripts/query-audit.sh. management_credentials does all four.

-- ---------------------------------------------------------------------------
-- The control-plane role.
--
-- Like ironauth_app (see 0001), this migration GRANTs to the role but NEVER
-- creates it and NEVER sets a password: shipping a CREATE ROLE ... PASSWORD
-- literal in a public repository would hand every reader a working credential
-- for the management plane. The role is provisioned out of band -- in production
-- by the operator, and in tests race-safely by the integration harness
-- (crates/ironauth-store/src/test_support.rs). If it is absent when this runs,
-- the GRANTs below fail loudly; that fail-closed behavior is intended.
--
-- ironauth_control is a peer of ironauth_app, not a superset: it is still NEVER
-- a superuser and NEVER a table owner, so FORCE ROW LEVEL SECURITY on the scoped
-- tables applies to it too. It gets the LEVEL tables (operators, tenants,
-- environments) that ironauth_app cannot see, plus append-only audit and the two
-- new management tables. It gets NOTHING on clients or organizations: the data
-- plane stays the data plane's.
GRANT USAGE ON SCHEMA public TO ironauth_control;

-- Level tables: the management plane creates and lists operators, tenants, and
-- environments. UPDATE (never DELETE) supports soft deactivation; the level
-- tables carry no per-row DELETE grant, so a hard delete is impossible.
GRANT SELECT, INSERT, UPDATE ON operators TO ironauth_control;
GRANT SELECT, INSERT, UPDATE ON tenants TO ironauth_control;
GRANT SELECT, INSERT, UPDATE ON environments TO ironauth_control;

-- Append-only audit, same shape as the data plane: SELECT and INSERT, never
-- UPDATE or DELETE. Every management mutation writes its audit row in the same
-- transaction as the mutation, through the same audited-write primitive.
GRANT SELECT, INSERT ON audit_log TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Soft deactivation for the level tables.
--
-- A NULL deleted_at means live; a non-NULL value is the deactivation instant
-- (sourced from the application clock seam, never the database clock). Reads
-- filter deleted_at IS NULL. The row is retained so the audit_log foreign keys
-- that reference it stay satisfiable forever, which is what makes DELETE
-- expressible at all against an append-only audit log.
ALTER TABLE tenants ADD COLUMN deleted_at timestamptz;
ALTER TABLE environments ADD COLUMN deleted_at timestamptz;

-- ---------------------------------------------------------------------------
-- Environment-scoped management API keys (mak_).
--
-- A tenant-scoped table, isolated exactly like clients: mandatory tenant_id and
-- environment_id, the nonempty-scope CHECK, forced row-level security keyed on
-- the same transaction-local session variables, and the same foreign keys.
--
-- The presented credential is `<mak_id>.<secret>`: the mak_ id embeds its
-- (tenant, environment) in the clear (it is a scoped identifier, safe to log),
-- and the secret is 256 bits of entropy (32 random bytes, URL-safe base64). Only
-- the SHA-256 of the whole token is stored (key_hash); the secret itself never
-- touches the database (the create path serializes a no-secret view into the
-- idempotency replay row, so a replay repeats no secret either). Because the
-- scope is recoverable from the id half of a presented token, the auth path can
-- bind the row-level-security scope and then look the credential up WITHIN it --
-- there is no unscoped lookup by hash.
CREATE TABLE management_credentials (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- SHA-256 (hex) of the full presented token. Never the secret itself.
    key_hash       text        NOT NULL,
    display_name   text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Soft revocation: NULL is live, non-NULL is the revocation instant.
    deleted_at     timestamptz,
    CONSTRAINT management_credentials_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX management_credentials_scope_idx
    ON management_credentials (tenant_id, environment_id);

ALTER TABLE management_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE management_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY management_credentials_tenant_isolation ON management_credentials
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The control role reads, creates, and soft-revokes (UPDATE) management keys; it
-- never hard-deletes one (no DELETE grant), so revocation history is retained.
GRANT SELECT, INSERT, UPDATE ON management_credentials TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Idempotency-Key replay store.
--
-- This table is deliberately CREDENTIAL-scoped, not tenant-row-level-security
-- scoped, and here is why: an operator-plane POST (create tenant) is looked up
-- for a replay BEFORE any tenant or environment exists, so it has no
-- (tenant, environment) scope to key row-level security on at check time. The
-- acting credential is the one stable scope every management request already has
-- (the bootstrap operator for the operator plane, or a mak_ key for the
-- environment plane, and a mak_ id itself embeds its (tenant, environment)). So
-- isolation here is by credential_ref, enforced by the WHERE clause on every
-- query, and the table is reachable only by the control role (no data-plane
-- grant, and it is still confined to the repository module by query-audit.sh).
--
-- A row stores the ORIGINAL response so a replay returns it verbatim without
-- re-executing the mutation (and therefore writing no second audit row). The
-- request_fingerprint (a hash of method + path + body) lets a key reused with a
-- DIFFERENT request be rejected rather than silently returning the wrong result.
CREATE TABLE idempotency_keys (
    -- The acting credential's audit-actor id (svc_... operator, or a mak_ id).
    credential_ref    text        NOT NULL,
    -- The client-supplied Idempotency-Key header value.
    idempotency_key   text        NOT NULL,
    -- Hash of method + path + body, to detect key reuse with a different request.
    request_fingerprint text      NOT NULL,
    -- The original response, replayed verbatim on a match.
    response_status   integer     NOT NULL,
    response_body     text        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (credential_ref, idempotency_key)
);

GRANT SELECT, INSERT ON idempotency_keys TO ironauth_control;
