-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- API keys and personal access tokens (issue #99, milestone M10).
--
-- One table for both, because they differ only in WHO owns them. A personal access token is
-- a key owned by a user; an API key is a key owned by a service account or an organization.
-- Two tables would duplicate the digest column, the revocation column, the expiry rule and
-- every verification path, and the two would drift.
--
--   1. The PLAINTEXT KEY IS NEVER STORED. `key_digest` holds the SHA-256 of the whole
--      presented key, exactly as `opaque_access_tokens` does (migration 0012), and it is the
--      lookup key: verification hashes what it was given and matches here. A key has 256 bits
--      of entropy, so a digest collision is not a threat model and no salt is needed; the
--      digest is unique globally and therefore within any scope.
--
--      The plaintext exists for the duration of the creation response and nowhere else. There
--      is deliberately no column it could be recovered from, which is what makes "retrievable
--      only in the creation response" a property of the schema rather than a promise about
--      the handlers.
--
--   2. `id` is a NON-SECRET handle (an `akey_` scoped id). List, rotate, revoke and every
--      audit row name this, never the digest and never the key. A management surface that had
--      to name keys by digest would put a verifier into its own audit log.
--
--   3. The OWNER is an exclusive arc. `owner_kind` says which of the three owner columns is
--      populated, and the CHECK enforces that exactly the matching one is non-NULL and the
--      other two are NULL. Modelled this way rather than as three nullable foreign keys with
--      no discriminator because criterion 1 turns on the owner: disabling an organization
--      invalidates its keys, disabling a user invalidates that user's keys and PATs, and a
--      row that does not say which it is cannot be swept by either.
--
--   4. NO metering columns, and that is a covenant rather than an omission. Issue #23 states
--      that M2M issuance is never metered or counted for billing, scripts/no-m2m-metering.sh
--      enforces it over the issuance path, and criterion 5 of issue #99 extends it to key
--      verification. There is no counter, no quota, no usage column here, and adding one
--      would break that covenant. `last_used_at` is deliberately absent too: it looks like
--      operational telemetry, but a monotonically written column on the verification path is
--      a write amplification on every authenticated request and the first step toward usage
--      accounting.
--
-- Migration safety obligation (see migrate.rs): a new tenant-scoped table ENABLEs and FORCEs
-- row-level security, adds the (tenant, environment) policy, adds the nonempty-scope CHECK,
-- and is registered in scripts/query-audit.sh. This does all four.

CREATE TABLE api_keys (
    -- The SHA-256 hex digest of the whole presented key. The verification lookup key.
    key_digest      text        PRIMARY KEY,
    -- The non-secret handle every management operation and audit row names.
    id              text        NOT NULL UNIQUE,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- Which owner column is populated. A closed vocabulary.
    owner_kind      text        NOT NULL,
    user_id         text,
    service_account_id text,
    organization_id text,
    -- The operator-facing label. Never secret, never part of the key.
    display_name    text        NOT NULL,
    -- Optional expiry, from the application clock seam (never the database clock), so
    -- resolution is deterministic under a manual clock in tests.
    expires_at      timestamptz,
    -- Set when revoked. A revoked key is RETAINED rather than deleted, and the reason is an
    -- APPLICATION rule rather than a foreign key: `audit_log` references only `tenants` and
    -- `environments`, so nothing in the schema would stop a DELETE here.
    --
    -- It is retained because revocation must be OBSERVABLE. A deleted row makes a revoked key
    -- indistinguishable from one that never existed, so an operator investigating a leak
    -- cannot tell "this key was revoked at 14:02" from "no such key", and a rotation leaves no
    -- trail linking the old handle to the new one. The audit rows naming this key's `id`
    -- outlive it either way; keeping the row is what makes them resolvable.
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT api_keys_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT api_keys_display_name_nonempty
        CHECK (display_name <> ''),
    CONSTRAINT api_keys_owner_kind_known
        CHECK (owner_kind IN ('user', 'service_account', 'organization')),
    -- The exclusive arc. Exactly the column named by `owner_kind` is populated.
    CONSTRAINT api_keys_owner_arc
        CHECK (
            (owner_kind = 'user'
                AND user_id IS NOT NULL
                AND service_account_id IS NULL
                AND organization_id IS NULL)
            OR (owner_kind = 'service_account'
                AND service_account_id IS NOT NULL
                AND user_id IS NULL
                AND organization_id IS NULL)
            OR (owner_kind = 'organization'
                AND organization_id IS NOT NULL
                AND user_id IS NULL
                AND service_account_id IS NULL)
        ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (service_account_id) REFERENCES service_accounts (id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The owner sweeps criterion 1 needs: "every live key of this organization", "every live key
-- of this user". Partial on the live rows, because a revoked key is never a sweep target.
CREATE INDEX api_keys_owner_user_live_idx
    ON api_keys (tenant_id, environment_id, user_id)
    WHERE revoked_at IS NULL AND user_id IS NOT NULL;

CREATE INDEX api_keys_owner_service_account_live_idx
    ON api_keys (tenant_id, environment_id, service_account_id)
    WHERE revoked_at IS NULL AND service_account_id IS NOT NULL;

CREATE INDEX api_keys_owner_organization_live_idx
    ON api_keys (tenant_id, environment_id, organization_id)
    WHERE revoked_at IS NULL AND organization_id IS NOT NULL;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY api_keys_scope_isolation ON api_keys
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane VERIFIES keys on the authentication path, so it reads and nothing else. It
-- holds no INSERT: minting a credential is a management act, and the plane that serves
-- unauthenticated traffic must not be able to mint one for itself.
GRANT SELECT ON api_keys TO ironauth_app;

-- The CONTROL plane creates, rotates and revokes. `UPDATE` is column-scoped to the two
-- columns a lifecycle operation touches (the #31 lesson): nothing may rewrite a digest, an
-- owner, or a scope after issue, because that would silently re-point a live credential at a
-- different principal.
GRANT SELECT, INSERT ON api_keys TO ironauth_control;
GRANT UPDATE (revoked_at, updated_at) ON api_keys TO ironauth_control;
