-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Bring-your-own-key (BYOK) bindings for the advanced-isolation rung (issue #49).
--
-- This EXTENDS the per-tenant envelope substrate (issue #48). That substrate seals
-- payloads under a per-(tenant, environment) DEK, wrapped under a per-scope KEK,
-- wrapped under a root. In the platform-key deployment the root is the platform
-- master key (tenant_keks.wrapped_kek holds the KEK sealed under it). BYOK is an
-- OPT-IN rung that lets a CUSTOMER-MANAGED root key (in an external KMS/HSM, or a
-- customer-supplied key) hold the root of a tenant's encryption instead, so the
-- customer can revoke it and revoking it crypto-shreds the tenant. BYOK is
-- EXPERIMENTAL and DEFAULT-OFF ([byok] enabled = false); a scope is BYOK-governed
-- only when the operator enrolls it and a binding row exists.
--
-- This migration persists ONLY the binding metadata: which KMS driver holds the
-- customer root, an OPAQUE external key REFERENCE (an ARN, a resource name, a key
-- URI), and the binding's lifecycle status. It NEVER stores a customer root key,
-- and it never stores key material of any kind: the wrap/unwrap of the tenant KEK
-- under the customer root is performed by the ironauth-kms driver seam, outbound
-- through the SSRF-hardened fetcher for an external driver. A reference is not a
-- secret; a customer root key never lands in this database in any form.
--
-- One binding per (tenant, environment) scope, isolated exactly like the envelope
-- key tables (0028): mandatory tenant_id and environment_id, the nonempty-scope
-- CHECK, forced row-level security keyed on the same transaction-local session
-- variables, and the same isolation-preserving foreign keys.
--
-- CRYPTO-SHREDDING OFFBOARDING (issue #46 terminal stage, deferred to this issue):
-- the tenant hard-delete (purge) severs a BYOK binding in the SAME audited
-- transaction that crypto-shreds the platform KEK: it flips status to 'destroyed',
-- clears the external key reference, and stamps destroyed_at, so the platform no
-- longer even points at the customer key and the binding is retained as erasure
-- evidence. A sibling tenant is unaffected because a binding is per-scope.
--
-- Migration safety obligation (see migrate.rs): the new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. All hold below. This migration is additive (one new
-- table), so it is an expand.

-- ---------------------------------------------------------------------------
-- Per-(tenant, environment) BYOK binding.
CREATE TABLE tenant_byok_bindings (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- Which KMS driver holds the customer root: 'local' is a customer-supplied
    -- in-process root (no external service); the other four reach an external
    -- KMS/HSM and are owner/infra-gated. The closed set matches the ironauth-kms
    -- KmsProviderKind and the ByokProvider config enum.
    provider       text        NOT NULL,
    -- The OPAQUE external key handle the driver addresses (an ARN, a resource
    -- name, a key URI). A non-secret reference, NEVER key material. Cleared to the
    -- empty string when the binding is severed at offboarding.
    key_ref        text        NOT NULL,
    -- 'active' (the binding governs the scope) or 'destroyed' (severed at the
    -- terminal offboarding stage; the row is retained as erasure evidence).
    status         text        NOT NULL DEFAULT 'active',
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- The sever instant (from the application clock seam), NULL while active.
    destroyed_at   timestamptz,
    -- One binding per scope, so a (tenant, environment) is governed by at most one
    -- customer root.
    PRIMARY KEY (tenant_id, environment_id),
    CONSTRAINT tenant_byok_bindings_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT tenant_byok_bindings_provider_valid
        CHECK (provider IN ('local', 'aws', 'gcp', 'azure', 'vault')),
    CONSTRAINT tenant_byok_bindings_status_valid
        CHECK (status IN ('active', 'destroyed')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX tenant_byok_bindings_scope_idx
    ON tenant_byok_bindings (tenant_id, environment_id);

ALTER TABLE tenant_byok_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_byok_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_byok_bindings_tenant_isolation ON tenant_byok_bindings
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane (ironauth_app) enrolls a scope in BYOK (INSERT) and reads its
-- binding (SELECT). It never mutates a binding: severing it is the terminal
-- offboarding action, and that runs on the control plane. No table-wide UPDATE
-- (the #31 lesson), no DELETE (bindings are retained as evidence).
GRANT SELECT, INSERT ON tenant_byok_bindings TO ironauth_app;

-- The CONTROL plane (ironauth_control) reads a binding and SEVERS it at the
-- terminal offboarding (purge) stage: a COLUMN-SCOPED UPDATE over exactly the
-- three columns the sever rewrites (the status, the cleared external reference,
-- and the sever instant), never a table-wide UPDATE. It gets no INSERT (enrolling
-- stays the data plane's) and no DELETE (the severed row is retained as erasure
-- evidence). The control role is never a superuser or table owner, so FORCE
-- row-level security applies to it too; the offboarding transaction binds each
-- (tenant, environment) scope before the sever.
GRANT SELECT ON tenant_byok_bindings TO ironauth_control;
GRANT UPDATE (status, key_ref, destroyed_at) ON tenant_byok_bindings TO ironauth_control;
