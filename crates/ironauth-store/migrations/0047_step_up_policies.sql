-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Step-up authentication policy surface (RFC 9470, issue #72).
--
-- This migration lands the DECLARATIVE authentication-requirement surface step-up
-- evaluates at authorization, at token issuance, and on refresh:
--
--   scope_step_up_policies: the per-scope tenant policy. One row per OAuth scope
--   token that carries an elevated authentication requirement, expressed as an
--   (acr floor, max auth age) pair. For example scope 'payments:write' requires
--   acr 'urn:ironauth:acr:mfa' within 300 seconds. A request that asks for a
--   governed scope must satisfy the policy or run a step-up; a scope with no row is
--   unaffected. It is a tenant-scoped resource: the id embeds its (tenant,
--   environment) and the table ENABLEs and FORCEs row-level security.
--
--   clients.step_up_acr / clients.step_up_max_age_secs: the per-CLIENT floor, an
--   additive extension of the client registration. It applies to EVERY request the
--   client makes, folded together with the request parameters and any per-scope
--   policy (the strongest acr floor and the smallest age window win).
--
--   refresh_families.auth_time: the recorded auth_time frozen onto the refresh
--   family at issuance, so a refresh can re-evaluate the max-age window WITHOUT a
--   new authentication. A family opened before this column existed (or a code that
--   carried no auth_time) leaves it NULL; a max-age policy evaluated against a NULL
--   auth_time on refresh FAILS CLOSED (the freshness cannot be proven, so the
--   window is treated as lapsed and a step-up is required), never a silent extend.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- The per-scope step-up policy (issue #72).
--
-- id is a `sup_` scoped identifier (embeds its (tenant, environment)), the audit
-- target and management handle. scope is the OAuth scope token the policy governs
-- (a single token such as 'payments:write', matched against each requested scope).
-- min_acr is the acr floor (NULL = no floor); max_auth_age_secs is the maximum
-- authentication age in seconds (NULL = no age bound). At least one of the two must
-- be set, so a policy row always constrains something.
-- ---------------------------------------------------------------------------
CREATE TABLE scope_step_up_policies (
    id                 text        NOT NULL,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The OAuth scope token this policy governs (a single scope value).
    scope              text        NOT NULL,
    -- The acr floor the authentication must achieve for this scope (NULL = none).
    min_acr            text,
    -- The maximum authentication age in seconds for this scope (NULL = no bound).
    max_auth_age_secs  integer,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    CONSTRAINT scope_step_up_policies_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scope_step_up_policies_scope_token_nonempty
        CHECK (scope <> ''),
    CONSTRAINT scope_step_up_policies_requirement_present
        CHECK (min_acr IS NOT NULL OR max_auth_age_secs IS NOT NULL),
    CONSTRAINT scope_step_up_policies_age_nonnegative
        CHECK (max_auth_age_secs IS NULL OR max_auth_age_secs >= 0),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- At most one policy per (scope, tenant, environment): a scope token has exactly
-- one governing requirement, so an upsert collapses onto this key.
CREATE UNIQUE INDEX scope_step_up_policies_scope_uk
    ON scope_step_up_policies (tenant_id, environment_id, scope);

-- The standard scope index for scope-filtered listing.
CREATE INDEX scope_step_up_policies_scope_idx
    ON scope_step_up_policies (tenant_id, environment_id);

ALTER TABLE scope_step_up_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_step_up_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_step_up_policies_tenant_isolation ON scope_step_up_policies
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Driven by the policy lifecycle: the evaluation path SELECTs, and management
-- upserts (INSERT ... ON CONFLICT DO UPDATE) and removes a policy.
GRANT SELECT, INSERT, UPDATE, DELETE ON scope_step_up_policies TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The per-client step-up floor (issue #72): additive registration columns,
-- mirroring the require_auth_time (0007) and require_pushed_authorization_requests
-- (0015) requirement-flag precedent. NULL means the client sets no floor.
-- ---------------------------------------------------------------------------
ALTER TABLE clients
    ADD COLUMN step_up_acr          text,
    ADD COLUMN step_up_max_age_secs integer;

-- The client column-scoped UPDATE grant (the #31 least-privilege lesson: 0018
-- REVOKEd the blanket UPDATE, so each additive column that the data plane may set
-- names itself here). The management seam sets the per-client floor through this.
GRANT UPDATE (step_up_acr, step_up_max_age_secs) ON clients TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The frozen auth_time on the refresh family (issue #72): the recorded
-- authentication instant (epoch microseconds) the refresh path re-evaluates the
-- max-age window against, without a new authentication. Nullable: a family opened
-- from a code that carried no auth_time leaves it NULL, and a max-age policy
-- evaluated against a NULL auth_time on refresh fails closed. refresh_families
-- already carries a table-level SELECT/INSERT/UPDATE grant to ironauth_app (0016),
-- which covers this additive column.
-- ---------------------------------------------------------------------------
ALTER TABLE refresh_families
    ADD COLUMN auth_time bigint;

-- ---------------------------------------------------------------------------
-- Widen the abuse-ban auth_path enumeration for the step-up second factor (issue
-- #72). The RFC 9470 step-up challenge (/login/mfa) and the self-service TOTP /
-- recovery-code verify surface (issue #69) are a NEW throttled authentication path,
-- AuthPath::SecondFactor, governed INDEPENDENTLY of the password and passkey paths
-- (the same per-path account-DoS safeguard, Keycloak CVE-2024-1722): a second-factor
-- guess storm may auto-place or an operator may set a 'second_factor' ban WITHOUT ever
-- touching the owner's password or passkey path. Migration 0046 pinned the closed path
-- set; this REPLACES that CHECK with one that also admits 'second_factor'. Widening a
-- CHECK to accept a new value is additive (no existing row can violate it and no reader
-- of an existing path breaks), so this stays an EXPAND.
ALTER TABLE abuse_bans DROP CONSTRAINT abuse_bans_auth_path_known;
ALTER TABLE abuse_bans ADD CONSTRAINT abuse_bans_auth_path_known
    CHECK (auth_path IN ('password', 'passkey', 'recovery', 'register', 'second_factor', 'all'));
