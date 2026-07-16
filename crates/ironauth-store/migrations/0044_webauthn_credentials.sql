-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- WebAuthn passkeys: the registered-credential registry and the single-use
-- ceremony challenge store (issue #65).
--
-- This migration lands the two pieces of persistent state a first-class passkey
-- surface needs, both NEW tenant-scoped tables with forced row-level security:
--
--   1. webauthn_credentials: one row per registered passkey. It holds the
--      credential id the authenticator minted, the COSE PUBLIC key (public key
--      material, NOT a bearer secret, so a plaintext bytea column, exactly as the
--      users table stores a password_hash in the clear), the signature counter
--      (for clone detection), the AAGUID, the client transports, the
--      backup-eligible (BE) and backup-state (BS) flags that distinguish a
--      device-bound authenticator from a synced one, the credProps rk result
--      (whether the credential is discoverable), and a clone-detected flag. The
--      user-authored nickname is PII, so it is sealed under the scope's envelope
--      DEK (issue #48), never a plaintext column, exactly like
--      account_credentials.friendly_name_sealed.
--
--   2. webauthn_challenges: the short-lived, single-use challenge each ceremony
--      is issued. The challenge is a public nonce (it is sent to the client in
--      the ceremony options), so it is a plaintext bytea; single use is enforced
--      by an atomic consumed_at UPDATE (a used or expired challenge is refused),
--      mirroring the pushed-authorization-request redeem (0015).
--
-- Migration safety obligation (see migrate.rs): both NEW tenant-scoped tables
-- ENABLE and FORCE row-level security, add the (tenant, environment) isolation
-- policy, add the nonempty-scope CHECK, and are registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The registered-passkey registry (issue #65).
--
-- id is a `pky_` scoped identifier (embeds its (tenant, environment)), so a
-- credential minted in one scope parses as a uniform not-found under another.
-- subject is the `usr_` id the passkey belongs to; every read and write filters
-- on it, so the surface only ever reaches the authenticated subject's own
-- credentials (the anti-IDOR contract). credential_id is the raw WebAuthn
-- credential id the authenticator minted; it is UNIQUE within a scope so the same
-- authenticator credential can never be registered twice (the excludeCredentials
-- dedupe, enforced at the database as well as in the ceremony). cose_public_key is
-- the verbatim COSE public key bytes, reconstructed at assertion time. sign_count
-- is the signature counter, compared and advanced under the row on every
-- assertion for clone detection. nickname_sealed is the user-authored label,
-- sealed under the scope's DEK (issue #48).
CREATE TABLE webauthn_credentials (
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The end-user subject (a `usr_` id) this passkey belongs to.
    subject           text        NOT NULL,
    -- The raw WebAuthn credential id the authenticator minted (public, not a
    -- secret; the authenticator echoes it on every assertion).
    credential_id     bytea       NOT NULL,
    -- The verbatim COSE_Key public key bytes (PUBLIC material, not sealed).
    cose_public_key   bytea       NOT NULL,
    -- The signature counter, advanced on each assertion (0 if unsupported).
    sign_count        bigint      NOT NULL DEFAULT 0,
    -- The authenticator model identifier (all-zero for privacy-preserving keys).
    aaguid            bytea       NOT NULL,
    -- The client-reported transports, space-separated (e.g. "internal hybrid").
    transports        text        NOT NULL DEFAULT '',
    -- Backup-eligible (BE): fixed for the credential life; a synced passkey sets it.
    backup_eligible   boolean     NOT NULL,
    -- Backup-state (BS): whether the credential is currently synced; may change.
    backup_state      boolean     NOT NULL,
    -- The credProps rk result: whether the credential is discoverable (NULL if
    -- the client did not report it).
    discoverable      boolean,
    -- Set when a sign-count regression flagged a possible cloned authenticator.
    clone_detected    boolean     NOT NULL DEFAULT false,
    -- The user-authored nickname, sealed under the scope's DEK (issue #48).
    nickname_sealed   bytea       NOT NULL,
    -- The DEK version the nickname was sealed under (for transparent open).
    pii_dek_version   integer     NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- When this passkey was last used to authenticate.
    last_used_at      timestamptz,
    CONSTRAINT webauthn_credentials_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX webauthn_credentials_scope_idx
    ON webauthn_credentials (tenant_id, environment_id);
-- The list reads a subject's credentials ordered by (created_at, id).
CREATE INDEX webauthn_credentials_subject_idx
    ON webauthn_credentials (tenant_id, environment_id, subject, created_at, id);
-- Dedupe: a WebAuthn credential id is unique within a (tenant, environment), so
-- an authenticator that already enrolled cannot register a duplicate row even if
-- the excludeCredentials client hint is bypassed.
CREATE UNIQUE INDEX webauthn_credentials_credential_id_idx
    ON webauthn_credentials (tenant_id, environment_id, credential_id);

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY webauthn_credentials_tenant_isolation ON webauthn_credentials
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane registers a passkey (INSERT), lists and inspects it (SELECT),
-- advances its counter / updates its backup state / stamps last-used / flags a
-- clone / renames it (a COLUMN-scoped UPDATE, never table-wide), and removes it
-- (DELETE). COLUMN-scoped UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON webauthn_credentials TO ironauth_app;
GRANT UPDATE (sign_count, backup_state, clone_detected, last_used_at, nickname_sealed, pii_dek_version)
    ON webauthn_credentials TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The single-use ceremony challenge store (issue #65).
--
-- id is a `wch_` scoped identifier (the challenge handle returned to the client).
-- ceremony is the closed set {register, authenticate}. subject is the `usr_` id a
-- registration challenge is bound to (NULL for a discoverable authentication,
-- whose subject is resolved from the assertion). challenge is the raw random
-- nonce, minted from the entropy seam; it is public (sent to the client), so a
-- plaintext bytea. Single use is the atomic consumed_at UPDATE: a challenge is
-- redeemed exactly once and a used or expired one is refused.
CREATE TABLE webauthn_challenges (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The ceremony this challenge was issued for, from the closed set.
    ceremony       text        NOT NULL,
    -- The subject a registration challenge is bound to (NULL for authentication).
    subject        text,
    -- The raw random challenge nonce (public, minted from the entropy seam).
    challenge      bytea       NOT NULL,
    -- NULL until redeemed; set once at single-use consumption.
    consumed_at    timestamptz,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webauthn_challenges_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT webauthn_challenges_ceremony_known
        CHECK (ceremony IN ('register', 'authenticate')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX webauthn_challenges_scope_idx
    ON webauthn_challenges (tenant_id, environment_id);
-- Pruning reads expired rows by (scope, expires_at).
CREATE INDEX webauthn_challenges_expiry_idx
    ON webauthn_challenges (tenant_id, environment_id, expires_at);

ALTER TABLE webauthn_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY webauthn_challenges_tenant_isolation ON webauthn_challenges
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane issues a challenge (INSERT), redeems it (SELECT + the atomic
-- consumed_at UPDATE), and prunes expired rows (DELETE). COLUMN-scoped UPDATE to
-- consumed_at alone (the #31 lesson).
GRANT SELECT, INSERT, DELETE ON webauthn_challenges TO ironauth_app;
GRANT UPDATE (consumed_at) ON webauthn_challenges TO ironauth_app;
