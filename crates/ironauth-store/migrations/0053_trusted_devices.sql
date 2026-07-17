-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Trusted devices: the remember-device second-factor state (issue #71).
--
-- After a COMPLETED multi-factor login (a genuine second factor, or a
-- user-verified passkey), a tenant may remember the device so a SUBSEQUENT login
-- from the same device skips the second factor while STILL requiring primary
-- authentication. The remembered device is a SIGNED, HttpOnly, Secure, __Host-
-- prefixed cookie carrying a device identifier that is BOUND TO SERVER-SIDE STATE
-- (this table), never a self-contained skip token: the cookie value proves nothing
-- on its own, so a replayed or forged cookie fails the server-side row check.
--
-- This migration lands ONE new tenant-scoped table with forced row-level security:
--
--   trusted_devices: one row per remembered device. It holds:
--     - a scope-embedded `tdv_` id (the device identifier the cookie names, which
--       embeds its (tenant, environment) so a device minted in one scope parses as
--       a uniform not-found under another);
--     - subject: the `usr_` id the device belongs to. Every read and write filters
--       on it (the anti-IDOR contract), so a device cookie for user A can never
--       skip the second factor for user B;
--     - device_secret_hash: the SHA-256 DIGEST of the high-entropy device secret
--       the cookie carries (never the self-contained secret, never reversible), so
--       a database dump reveals no usable cookie value. A presented cookie is
--       validated by hashing its secret and matching this digest AND checking the
--       row is live (not revoked, within its max-age and idle windows);
--     - session_lineage: the `ses_` id of the multi-factor session the device was
--       remembered from (the lineage the trust descends from), recorded for the
--       account UI and audit;
--     - user_agent_sealed / geo_sealed: the observed User-Agent and coarse location
--       at enrollment, each SEALED under the scope's envelope DEK (issue #48) since
--       they are end-user device metadata (PII); pii_dek_version records the DEK
--       they were sealed under, for transparent open on read and export;
--     - created_at / last_seen_at: shown in the M6 device list;
--     - max_age_expires_at / idle_expires_at: the per-tenant duration policy the
--       row was minted under (an absolute cap and a sliding idle window), enforced
--       authoritatively in the read query so an out-of-policy device stops skipping
--       IMMEDIATELY rather than lingering;
--     - revoked_at / revoke_reason: set exactly once when the user revokes the
--       device, an admin acts, or a password change/reset or factor change
--       invalidates trust. A revoked row stops satisfying the skip in the SAME read,
--       so a replayed cookie after revocation FAILS server-side, not just by
--       signature.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- ENABLES and FORCES row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- The remembered-device registry (issue #71).
--
-- id is a `tdv_` scoped identifier (embeds its (tenant, environment)), so a device
-- minted in one scope parses as a uniform not-found under another. subject is the
-- `usr_` id the device belongs to; every read and write filters on it, so the
-- surface only ever reaches the authenticated subject's own devices (anti-IDOR).
-- device_secret_hash is the SHA-256 digest of the cookie's high-entropy secret
-- (server-side state, never the secret itself). user_agent_sealed and geo_sealed
-- are sealed under the scope's active DEK (issue #48); pii_dek_version records the
-- DEK they were sealed under. The two expiry columns are the duration policy the
-- device was minted under; revoked_at is the immediate server-side kill switch.
CREATE TABLE trusted_devices (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The end-user subject (a `usr_` id) this remembered device belongs to.
    subject             text        NOT NULL,
    -- The SHA-256 digest of the cookie's high-entropy device secret (issue #71):
    -- server-side state, never the self-contained secret. A presented cookie is
    -- validated by hashing its secret to this digest AND checking the row is live.
    device_secret_hash  bytea       NOT NULL,
    -- The `ses_` session the device was remembered from (the multi-factor login the
    -- trust descends from), for the account UI and audit lineage.
    session_lineage     text        NOT NULL,
    -- The observed User-Agent at enrollment, sealed under the scope's DEK (issue
    -- #48). End-user device metadata (PII): never a plaintext column.
    user_agent_sealed   bytea       NOT NULL,
    -- The coarse location (a /24 or /48 prefix) at enrollment, sealed under the
    -- scope's DEK (issue #48). Never a plaintext column.
    geo_sealed          bytea       NOT NULL,
    -- The DEK version the user-agent and geo were sealed under.
    pii_dek_version     integer     NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- When the device was last used to skip a second factor (the M6 last-seen).
    last_seen_at        timestamptz,
    -- The absolute max-age cap the device was minted under: past it the device
    -- never skips again (enforced authoritatively in the read query).
    max_age_expires_at  timestamptz NOT NULL,
    -- The sliding idle window: a use past roughly half the window advances it, so an
    -- unused device expires at idle while an active one lives to the absolute cap.
    idle_expires_at     timestamptz NOT NULL,
    -- Set exactly once when the device is revoked (user, admin, or a
    -- password/factor-change invalidation). A revoked row stops skipping IMMEDIATELY.
    revoked_at          timestamptz,
    -- The closed reason set for a revocation (audit / UI legibility).
    revoke_reason       text,
    CONSTRAINT trusted_devices_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed revoke-reason set: an unknown reason can never be written, and the
    -- reason is present exactly when the row is revoked.
    CONSTRAINT trusted_devices_revoke_reason_known
        CHECK (
            (revoked_at IS NULL AND revoke_reason IS NULL)
            OR (revoked_at IS NOT NULL AND revoke_reason IN (
                'user', 'admin', 'password_change', 'factor_change'
            ))
        ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX trusted_devices_scope_idx
    ON trusted_devices (tenant_id, environment_id);
-- The self-service list and the export read a subject's rows ordered by (created_at, id).
CREATE INDEX trusted_devices_subject_idx
    ON trusted_devices (tenant_id, environment_id, subject, created_at, id);
-- A presented cookie resolves the ONE candidate row by its secret digest (issue
-- #71), so validation checks a single row rather than scanning the subject's set.
CREATE UNIQUE INDEX trusted_devices_secret_hash_idx
    ON trusted_devices (tenant_id, environment_id, device_secret_hash);

ALTER TABLE trusted_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY trusted_devices_tenant_isolation ON trusted_devices
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane remembers a device (INSERT), validates and lists it (SELECT),
-- slides its idle window and stamps last-seen on a use (a COLUMN-scoped UPDATE),
-- revokes it (a COLUMN-scoped UPDATE to revoked_at/revoke_reason), and clears a
-- prior device on re-enrollment (DELETE). COLUMN-scoped UPDATE only (the #31
-- least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON trusted_devices TO ironauth_app;
GRANT UPDATE (last_seen_at, idle_expires_at, revoked_at, revoke_reason)
    ON trusted_devices TO ironauth_app;
-- The exit-export surface reads the sealed device metadata for the account export
-- (issue #58 covenant): SELECT and INSERT, no more (least privilege, mirroring 0045).
GRANT SELECT, INSERT ON trusted_devices TO ironauth_control;
