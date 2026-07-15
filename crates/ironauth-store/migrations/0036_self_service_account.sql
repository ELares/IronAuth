-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Self-service account management: password change and the credential registry
-- (issue #61).
--
-- The end-user account surface (issue #61) lets an AUTHENTICATED user manage
-- their OWN account: list and revoke their OWN sessions (already authoritative in
-- Postgres from the session model, issue #32, so listing and revoking is a scoped
-- read/write of existing state, no new table), CHANGE their OWN password (the
-- bootstrap Argon2id credential from issue #20), and enroll/list/remove their OWN
-- credentials (passkeys, TOTP, recovery codes). This migration lands the two
-- pieces of persistent state that surface needs beyond what already exists:
--
--   1. A column-scoped UPDATE grant on `users.password_hash`, so the data-plane
--      role can REPLACE a user's Argon2id verifier at a self-service password
--      change. The bootstrap users table (0006) granted only SELECT and INSERT
--      (no account lifecycle); the self-service password change is the first
--      mutation of an existing user row, and it needs exactly this one column,
--      never a table-wide UPDATE (the #31 least-privilege lesson). The plaintext
--      password never reaches a column: the caller computes the new Argon2id PHC
--      verifier through the entropy seam and passes only the hash, exactly as
--      registration does.
--
--   2. A NEW tenant-scoped `account_credentials` table: the per-user registry of
--      enrolled credentials (passkeys, TOTP authenticators, recovery-code sets).
--      This issue ships the ENDPOINTS and the AUTHORIZATION CONTRACT (a credential
--      is bound to its subject and only ever reachable by that subject); the
--      concrete factor material and ceremonies wire in as the M7 factor issues
--      land. A credential's friendly name is user-authored PII, so it is sealed
--      under the scope's envelope DEK (issue #48), never a plaintext column; the
--      row otherwise carries only non-sensitive metadata (the factor type, whether
--      it is usable as a primary login credential, and the created / last-used
--      timestamps the account UI shows).
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (account_credentials) ENABLEs and FORCEs row-level security, adds the (tenant,
-- environment) isolation policy, adds the nonempty-scope CHECK, and is registered
-- in scripts/query-audit.sh. The users grant is a pure additive column-scoped
-- grant. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. Let the data plane REPLACE a user's password hash at a self-service change.
--
-- COLUMN-scoped to password_hash alone: the self-service change verifies the
-- CURRENT password (against the SELECTed hash) and then writes the NEW Argon2id
-- verifier. No other users column is ever updated through this surface, so the
-- grant is exactly one column, never a table-wide UPDATE (the #31 lesson). The
-- identifier (a #48 blind index plus sealed value) and the sealed claims are
-- untouched by a password change.
GRANT UPDATE (password_hash) ON users TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per-user enrolled-credential registry (issue #61).
--
-- id is a `crd_` scoped identifier (embeds its (tenant, environment)), so a
-- credential id minted in one scope parses as a uniform not-found under another.
-- subject is the `usr_` id the credential belongs to; every self-service read and
-- write filters on it, so the surface only ever reaches the authenticated
-- subject's own credentials (the anti-IDOR contract of this issue). credential_type
-- is the closed factor set the M7 issues implement against. friendly_name_sealed is
-- the user-authored label ("my work laptop"), sealed under the scope's envelope DEK
-- (issue #48): user PII never lands on a plaintext column. usable_for_login marks a
-- credential that can serve as a PRIMARY login factor (a passkey), which the
-- last-usable-credential guardrail counts so a user cannot silently strand
-- themselves. last_used_at is stamped by the (M7) factor verification path.
CREATE TABLE account_credentials (
    id                   text        PRIMARY KEY,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,
    -- The end-user subject (a `usr_` id) this credential belongs to.
    subject              text        NOT NULL,
    -- The factor kind, from the closed set the M7 factor issues implement.
    credential_type      text        NOT NULL,
    -- The user-authored friendly name, sealed under the scope's DEK (issue #48).
    friendly_name_sealed bytea       NOT NULL,
    -- The DEK version the friendly name was sealed under (for transparent open).
    pii_dek_version      integer     NOT NULL,
    -- Whether this credential can serve as a PRIMARY login factor (the guardrail
    -- counts these so removing the last one is blocked).
    usable_for_login     boolean     NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- When the factor was last used to authenticate, stamped by the M7 verify path.
    last_used_at         timestamptz,
    CONSTRAINT account_credentials_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed factor set: an unknown type can never be written.
    CONSTRAINT account_credentials_type_known
        CHECK (credential_type IN ('passkey', 'totp', 'recovery_code')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX account_credentials_scope_idx
    ON account_credentials (tenant_id, environment_id);
-- The self-service list reads a subject's credentials ordered by (created_at, id).
CREATE INDEX account_credentials_subject_idx
    ON account_credentials (tenant_id, environment_id, subject, created_at, id);

ALTER TABLE account_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY account_credentials_tenant_isolation ON account_credentials
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane enrolls a credential (INSERT), lists and inspects it (SELECT),
-- renames it or stamps its last-used time (a COLUMN-scoped UPDATE, never
-- table-wide), and removes it (DELETE). The audit row for a removal survives the
-- DELETE (audit_log carries the id as text, not a foreign key). COLUMN-scoped
-- UPDATE only (the #31 lesson).
GRANT SELECT, INSERT, DELETE ON account_credentials TO ironauth_app;
GRANT UPDATE (friendly_name_sealed, last_used_at)
    ON account_credentials TO ironauth_app;
