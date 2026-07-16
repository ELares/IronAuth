-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Credential-abuse defenses: durable, DB-backed ban state (issue #64).
--
-- This migration lands the ONE new piece of persistent state the credential-abuse
-- subsystem needs beyond the generic fixed-window counter: a durable ban registry
-- that survives a server restart and is managed through the CLI and the admin API.
--
--   abuse_bans: one row per active ban over a SINGLE regulated dimension and a
--   SINGLE authentication path. The dimension is an attacker IP, an account, or a
--   canonical identifier (the #54 seam output, so a case/unicode variant of an
--   identifier can never bypass a ban). The subject value is PII (an identifier is
--   an email/username/phone; an IP is personal data), so it is NEVER stored in the
--   clear: it is sealed under the scope's envelope DEK (issue #48) for an authorized
--   CLI/admin view, and a keyed per-tenant HMAC blind index (issue #48) is stored for
--   the equality lookup the request path makes. The auth_path column is the
--   account-DoS safeguard (Keycloak CVE-2024-1722): a `password` ban never governs
--   the `passkey` or `recovery` path, so failed-password spray against a victim can
--   never lock the legitimate owner out of every path.
--
-- The high-frequency, ephemeral LAYERED failure counters (per-IP, per-account,
-- per-identifier, per-client, per-(tenant,environment)) deliberately REUSE the
-- generic dcr_rate_counters fixed-window table (0018) with an `abuse:` key
-- namespace, exactly as the device-verification surface (0021/#24) reuses it, so
-- this migration adds no second counter table.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table ENABLEs
-- and FORCEs row-level security, adds the (tenant, environment) isolation policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The durable ban registry (issue #64).
--
-- id is an `abn_` scoped identifier (embeds its (tenant, environment)), so a ban
-- minted in one scope parses as a uniform not-found under another; it is the CLI /
-- admin handle and the audit target. subject_kind names the regulated dimension.
-- subject_bidx is the keyed per-tenant HMAC of (kind, subject value), the value the
-- request-path equality lookup and the per-(kind, path) uniqueness query use; the
-- per-tenant key means the SAME identifier in two tenants maps to two different tags.
-- subject_sealed is the AEAD-sealed subject value, opened only for an authorized
-- CLI/admin listing. auth_path scopes the ban to one authentication path. reason is
-- an operator-supplied, operator-safe string (never attacker-controlled request-path
-- free text). expires_at NULL is a permanent ban; a set value auto-expires.
-- ---------------------------------------------------------------------------
CREATE TABLE abuse_bans (
    id              text        NOT NULL,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The regulated dimension: 'ip' | 'account' | 'identifier'.
    subject_kind    text        NOT NULL,
    -- Keyed per-tenant HMAC blind index of (kind, canonical subject value): the
    -- equality-searchable lookup key. Never the plaintext subject.
    subject_bidx    bytea       NOT NULL,
    -- The subject value sealed under the scope's active DEK (issue #48), opened only
    -- for an authorized CLI/admin view.
    subject_sealed  bytea       NOT NULL,
    -- The DEK version the subject was sealed under (for transparent open).
    pii_dek_version integer     NOT NULL,
    -- The authentication path this ban governs: 'password' | 'passkey' | 'recovery'
    -- | 'register' | 'all'. Per-path isolation is the account-DoS safeguard.
    auth_path       text        NOT NULL,
    -- Operator-safe reason (CLI/admin supplied), never attacker free text.
    reason          text        NOT NULL,
    -- NULL = permanent; a set value is the auto-expiry instant.
    expires_at      timestamptz,
    created_at      timestamptz NOT NULL,
    CONSTRAINT abuse_bans_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT abuse_bans_subject_kind_known
        CHECK (subject_kind IN ('ip', 'account', 'identifier')),
    CONSTRAINT abuse_bans_auth_path_known
        CHECK (auth_path IN ('password', 'passkey', 'recovery', 'register', 'all')),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- At most one active ban per (scope, dimension, subject, path): re-banning the same
-- subject on the same path is a conflict the write path collapses to idempotence.
CREATE UNIQUE INDEX abuse_bans_subject_path_uk
    ON abuse_bans (tenant_id, environment_id, subject_kind, subject_bidx, auth_path);

-- The standard scope index for scope-filtered listing.
CREATE INDEX abuse_bans_scope_idx ON abuse_bans (tenant_id, environment_id);

ALTER TABLE abuse_bans ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_bans FORCE ROW LEVEL SECURITY;
CREATE POLICY abuse_bans_tenant_isolation ON abuse_bans
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Driven by the ban lifecycle: INSERT bans one dimension+path, DELETE lifts it, and
-- the request path plus the CLI/admin listing SELECT. A ban row is immutable once
-- written (change = lift then re-ban), so no UPDATE grant is issued.
GRANT SELECT, INSERT, DELETE ON abuse_bans TO ironauth_app;
