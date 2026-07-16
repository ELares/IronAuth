-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Credential-class policy: the per-scope minimum-credential-class ladder, the
-- attestation configuration surface, and the passkey-only account markers on the
-- users table (issue #66, PR A).
--
-- This migration lands the DECLARATIVE credential-policy surface the authentication
-- and enrollment paths compose with strictest-wins semantics:
--
--   credential_class_policies: the per-scope minimum-class policy. Each row attaches
--   a minimum credential class ('any' < 'mfa' < 'passkey' < 'attested_passkey') to a
--   policy SUBJECT: the tenant itself, a group, or an organization. In v1 only the
--   single tenant-level row is APPLICABLE at authentication; the group and org rows
--   are the inert attachment seam (end-to-end group/org attachment lands with the M10
--   organization model), but the schema carries the discriminator now so the
--   composition algorithm is complete. A tenant-scoped resource: the id embeds its
--   (tenant, environment) and the table ENABLEs and FORCEs row-level security.
--
--   attestation_config: the per-scope attestation mode ('none' default, or 'direct').
--   PR A ships this row DORMANT (nothing reads it to gate a registration yet); PR B
--   adds the FIDO MDS3 cache and the per-tenant AAGUID allow/deny lists that the
--   'direct' mode evaluates. It completes the config surface here so PR B is purely
--   additive. A tenant-scoped resource with forced row-level security.
--
--   users.webauthn_user_handle: the stable per-user WebAuthn user handle, IMMUTABLE
--   after creation (the Kratos #4519 bug class: a mutated user_handle orphans every
--   registered passkey). Immutability is enforced at TWO layers: the column is OMITTED
--   from every GRANT UPDATE on users (least privilege, so the data-plane role cannot
--   name it), AND a BEFORE UPDATE trigger RAISEs if a row with a non-NULL handle is
--   updated to a DIFFERENT handle. The nullable first-set is allowed (a legacy row
--   with no handle can receive one exactly once); a set handle can never change.
--
--   users.passwordless: the "this account never had a usable password hash" marker
--   for a first-class passkey-only account. PR A adds the column DEFAULT false and its
--   column-scoped UPDATE grant; PR C flips it during passkey-only signup / conversion.
--
-- Migration safety obligation (see migrate.rs): the two NEW tenant-scoped tables
-- ENABLE and FORCE row-level security, add the (tenant, environment) isolation
-- policy, add the nonempty-scope CHECK, and are registered in
-- scripts/query-audit.sh. The users additions are additive columns plus a guard
-- trigger. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The per-scope minimum-credential-class policy (issue #66).
--
-- id is a `ccp_` scoped identifier (embeds its (tenant, environment)), the audit
-- target and management handle. subject_kind is the closed set {tenant, group, org}
-- the policy attaches to; subject_ref is the group/org id it names (NULL for the
-- tenant-wide row). min_class is the minimum class from the closed ladder set. The
-- composition folds every APPLICABLE row's min_class with strictest-wins (max), so a
-- stronger row always dominates.
-- ---------------------------------------------------------------------------
CREATE TABLE credential_class_policies (
    id                 text        NOT NULL,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The policy subject: the tenant itself, a group, or an organization.
    subject_kind       text        NOT NULL,
    -- The group / org id the policy names (NULL for the tenant-wide row).
    subject_ref        text,
    -- The minimum credential class from the closed ladder set.
    min_class          text        NOT NULL,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    CONSTRAINT credential_class_policies_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT credential_class_policies_subject_kind_known
        CHECK (subject_kind IN ('tenant', 'group', 'org')),
    CONSTRAINT credential_class_policies_min_class_known
        CHECK (min_class IN ('any', 'mfa', 'passkey', 'attested_passkey')),
    -- The tenant-wide row carries NO subject_ref; a group / org row MUST name a
    -- nonempty one. This ties the discriminator to its target so a malformed row
    -- (a tenant row with a ref, or a group row without one) can never be written.
    CONSTRAINT credential_class_policies_subject_ref_presence
        CHECK (
            (subject_kind = 'tenant' AND subject_ref IS NULL)
            OR (subject_kind IN ('group', 'org') AND subject_ref IS NOT NULL AND subject_ref <> '')
        ),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- At most one policy per (subject_kind, subject_ref, tenant, environment): a subject
-- has exactly one governing minimum, so an upsert collapses onto this key. The
-- COALESCE folds the NULL tenant ref to '' so the tenant-wide row is unique too.
CREATE UNIQUE INDEX credential_class_policies_subject_uk
    ON credential_class_policies (tenant_id, environment_id, subject_kind, COALESCE(subject_ref, ''));

-- The standard scope index for scope-filtered listing / composition reads.
CREATE INDEX credential_class_policies_scope_idx
    ON credential_class_policies (tenant_id, environment_id);

ALTER TABLE credential_class_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_class_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_class_policies_tenant_isolation ON credential_class_policies
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The composition path SELECTs, and management upserts (INSERT ... ON CONFLICT DO
-- UPDATE) and removes a policy. COLUMN-scoped UPDATE only (the #31 least-privilege
-- lesson): only min_class and updated_at may change on an upsert; the scope and the
-- subject discriminator are immutable (a different subject is a different row).
GRANT SELECT, INSERT, DELETE ON credential_class_policies TO ironauth_app;
GRANT UPDATE (min_class, updated_at) ON credential_class_policies TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per-scope attestation configuration (issue #66, dormant in PR A).
--
-- id is an `atc_` scoped identifier. mode is the closed set {none, direct}: 'none'
-- (the default) requests no attestation, 'direct' requests and validates it against
-- FIDO MDS3 (the validation and the AAGUID allow/deny lists land in PR B). One row
-- per (tenant, environment): the mode is a scope-wide switch.
-- ---------------------------------------------------------------------------
CREATE TABLE attestation_config (
    id                 text        NOT NULL,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The attestation conveyance mode: 'none' (default) or 'direct'.
    mode               text        NOT NULL DEFAULT 'none',
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    CONSTRAINT attestation_config_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT attestation_config_mode_known
        CHECK (mode IN ('none', 'direct')),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- Exactly one attestation config per (tenant, environment): the scope-wide switch.
CREATE UNIQUE INDEX attestation_config_scope_uk
    ON attestation_config (tenant_id, environment_id);

ALTER TABLE attestation_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_config FORCE ROW LEVEL SECURITY;
CREATE POLICY attestation_config_tenant_isolation ON attestation_config
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Management upserts the mode (INSERT ... ON CONFLICT DO UPDATE) and reads it
-- (SELECT). COLUMN-scoped UPDATE to mode / updated_at only (the #31 lesson); there is
-- no DELETE (a config is reset by setting mode back to 'none', never removed).
GRANT SELECT, INSERT ON attestation_config TO ironauth_app;
GRANT UPDATE (mode, updated_at) ON attestation_config TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. The passkey-only account markers on the users table (issue #66).
--
-- webauthn_user_handle is the stable per-user WebAuthn user handle. It is added
-- NULLABLE (a legacy row has none until a passkey ceremony sets it once) and is
-- IMMUTABLE once set: the Kratos #4519 bug class is that a mutated user_handle
-- silently orphans every registered passkey. passwordless marks a first-class
-- passkey-only account (PR C flips it); it defaults false so every existing row is a
-- password-holding account.
-- ---------------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN webauthn_user_handle bytea,
    ADD COLUMN passwordless         boolean NOT NULL DEFAULT false;

-- The user-handle immutability trigger (the storage-layer half of the guarantee; the
-- other half is the deliberate OMISSION of webauthn_user_handle from every GRANT
-- UPDATE on users, so the data-plane role cannot even name it). A row whose handle is
-- already set can never change it: the trigger RAISEs on any UPDATE that would move a
-- non-NULL handle to a DIFFERENT value. Setting a NULL handle to a value once (the
-- first bind) and an idempotent no-op UPDATE both pass. IS DISTINCT FROM is NULL-safe.
CREATE FUNCTION users_user_handle_immutable() RETURNS trigger AS $$
BEGIN
    IF OLD.webauthn_user_handle IS NOT NULL
       AND NEW.webauthn_user_handle IS DISTINCT FROM OLD.webauthn_user_handle THEN
        RAISE EXCEPTION 'users.webauthn_user_handle is immutable once set (issue #66)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_user_handle_immutable
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION users_user_handle_immutable();

-- The passwordless marker's column-scoped UPDATE grant (the #31 least-privilege
-- lesson): PR C flips this flag during passkey-only signup / conversion. The
-- webauthn_user_handle column is DELIBERATELY absent from this grant (and every other
-- users GRANT UPDATE), so the data-plane role has no privilege to mutate it at all,
-- reinforcing the trigger with a least-privilege denial.
GRANT UPDATE (passwordless) ON users TO ironauth_app;
