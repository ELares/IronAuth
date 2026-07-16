-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- TOTP authenticators and recovery codes: the second-factor state (issue #69).
--
-- This migration lands the two pieces of persistent state a first-class TOTP
-- surface needs, both NEW tenant-scoped tables with forced row-level security:
--
--   1. totp_credentials: one row per enrolled TOTP authenticator. It holds the
--      shared secret SEED sealed under the scope's envelope DEK (issue #48) so a
--      database leak without the tenant KEK exposes no seed and tenant
--      offboarding crypto-shreds it. A seed is long-lived shared secret material,
--      exactly the class the M5 envelope substrate was built for, so it is NEVER
--      a plaintext column: totp_seed is a sealed bytea, mirroring how a user
--      identifier or a webauthn nickname is sealed. The row also carries the
--      RFC 6238 parameters (algorithm, digits, period), the enrollment status
--      (pending until the user proves possession with a valid code, active
--      thereafter, so an ABANDONED enrollment leaves no active factor), the
--      last-consumed time-step (the hard single-use anti-replay invariant: a
--      (credential, time-step) pair verifies at most once), and the last observed
--      drift offset (resync). The user-authored friendly name is PII, sealed under
--      the same DEK, exactly like account_credentials.friendly_name_sealed.
--
--   2. recovery_codes: the per-user one-time recovery codes generated at MFA
--      enrollment. Each code is a shared secret the user knows, so it is stored
--      HASHED with the SAME Argon2id password-hashing infrastructure (issue #62)
--      as a password verifier: code_hash is a one-way PHC string (never a
--      plaintext code, never reversible), so a database dump reveals no usable
--      code. Each row is single-use (consumed_at is set exactly once at
--      redemption); regeneration deletes the whole prior batch and inserts a
--      fresh generation, so regeneration invalidates every outstanding code.
--
-- Migration safety obligation (see migrate.rs): both NEW tenant-scoped tables
-- ENABLE and FORCE row-level security, add the (tenant, environment) isolation
-- policy, add the nonempty-scope CHECK, and are registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.
--
-- Deliberately NO HOTP: there is no counter column a caller can drive and no
-- counter-based configuration anywhere. The only time-step this schema tracks is
-- derived from wall-clock time (unix_time / period), enforced by the
-- algorithm-known CHECK below (only the three RFC 6238 hashes) and the absence of
-- any HOTP code path.

-- ---------------------------------------------------------------------------
-- 1. The enrolled-TOTP-authenticator registry (issue #69).
--
-- id is a `tot_` scoped identifier (embeds its (tenant, environment)), so a
-- credential minted in one scope parses as a uniform not-found under another.
-- subject is the `usr_` id the authenticator belongs to; every read and write
-- filters on it, so the surface only ever reaches the authenticated subject's own
-- factor (the anti-IDOR contract). totp_seed is the RFC 6238 shared secret sealed
-- under the scope's active DEK (issue #48); pii_dek_version records the DEK the
-- seed and the friendly name were sealed under, for transparent open on read and
-- export. status is 'pending' until the user proves possession, then 'active';
-- an abandoned enrollment stays pending and never satisfies MFA. last_consumed_step
-- is NULL until the first successful verification and is then advanced strictly
-- upward, which is the single-use anti-replay invariant. last_offset records the
-- last matched drift offset for resync visibility.
CREATE TABLE totp_credentials (
    id                   text        PRIMARY KEY,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,
    -- The end-user subject (a `usr_` id) this authenticator belongs to.
    subject              text        NOT NULL,
    -- The RFC 6238 shared secret SEED, sealed under the scope's DEK (issue #48).
    -- Secret material: never a plaintext column, never returned after enrollment.
    totp_seed            bytea       NOT NULL,
    -- The user-authored friendly name, sealed under the scope's DEK (issue #48).
    friendly_name_sealed bytea       NOT NULL,
    -- The DEK version the seed and friendly name were sealed under.
    pii_dek_version      integer     NOT NULL,
    -- The RFC 6238 hash (the closed set; no HOTP, no other primitive).
    algorithm            text        NOT NULL DEFAULT 'SHA1',
    -- The number of decimal digits in a code (6 is the authenticator-app default).
    digits               integer     NOT NULL DEFAULT 6,
    -- The time-step period in seconds (30 is the RFC 6238 default).
    period_secs          integer     NOT NULL DEFAULT 30,
    -- The enrollment status: 'pending' (unverified, cannot satisfy MFA) or 'active'.
    status               text        NOT NULL DEFAULT 'pending',
    -- The last time-step consumed by a successful verification (single-use spine):
    -- a verification advances this strictly upward, so a replayed (or drifted)
    -- code at a step less than or equal to it is refused. NULL before first use.
    last_consumed_step   bigint,
    -- The last matched drift offset (resync visibility). NULL before first use.
    last_offset          integer,
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- When the factor was activated (the code-verified enrollment). NULL while pending.
    activated_at         timestamptz,
    -- When the factor was last used to authenticate.
    last_used_at         timestamptz,
    CONSTRAINT totp_credentials_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed status set: an unknown status can never be written.
    CONSTRAINT totp_credentials_status_known
        CHECK (status IN ('pending', 'active')),
    -- The closed RFC 6238 hash set: no HOTP, no other primitive.
    CONSTRAINT totp_credentials_algorithm_known
        CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    -- The accepted code width and period (mirrors the ironauth-jose TotpParams bounds).
    CONSTRAINT totp_credentials_digits_range
        CHECK (digits BETWEEN 6 AND 8),
    CONSTRAINT totp_credentials_period_range
        CHECK (period_secs BETWEEN 15 AND 60),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX totp_credentials_scope_idx
    ON totp_credentials (tenant_id, environment_id);
-- The self-service list and the export read a subject's rows ordered by (created_at, id).
CREATE INDEX totp_credentials_subject_idx
    ON totp_credentials (tenant_id, environment_id, subject, created_at, id);
-- At most one ACTIVE TOTP authenticator per subject: a partial unique index over
-- the active rows, so a second activation cannot silently strand the first factor.
-- Pending rows are unconstrained (a fresh enrollment replaces a stale pending one).
CREATE UNIQUE INDEX totp_credentials_active_idx
    ON totp_credentials (tenant_id, environment_id, subject)
    WHERE status = 'active';

ALTER TABLE totp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE totp_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY totp_credentials_tenant_isolation ON totp_credentials
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane begins an enrollment (INSERT a pending row), lists and verifies
-- it (SELECT), activates it and advances its single-use step / resync offset /
-- last-used time (a COLUMN-scoped UPDATE, never table-wide), and removes it
-- (DELETE). COLUMN-scoped UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON totp_credentials TO ironauth_app;
GRANT UPDATE (status, last_consumed_step, last_offset, activated_at, last_used_at)
    ON totp_credentials TO ironauth_app;
-- The exit-export surface reads the sealed seed and re-enrolls it under a fresh
-- user (issue #58 covenant), so the control plane needs SELECT and INSERT, and no
-- more (no UPDATE / DELETE: least privilege, mirroring 0042 for account_credentials).
GRANT SELECT, INSERT ON totp_credentials TO ironauth_control;

-- ---------------------------------------------------------------------------
-- 2. The one-time recovery-code store (issue #69).
--
-- id is a `rvc_` scoped identifier. subject is the `usr_` id the code belongs to;
-- every read and write filters on it (anti-IDOR). code_hash is the Argon2id PHC
-- verifier of the code, minted through the admission-controlled hashing pool
-- (issue #62), so a code is stored exactly as a password: one-way, never
-- reversible, never a plaintext column. generation is the batch a code was minted
-- in; a full regeneration deletes the prior batch and inserts a higher generation,
-- so every outstanding code is invalidated at once. consumed_at is set exactly
-- once at redemption (single-use).
CREATE TABLE recovery_codes (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The end-user subject (a `usr_` id) this recovery code belongs to.
    subject        text        NOT NULL,
    -- The Argon2id PHC verifier of the code (issue #62). One-way, never a plaintext
    -- code: a database dump reveals no usable code.
    code_hash      text        NOT NULL,
    -- The per-scope keyed BLIND INDEX of the normalized code (issue #69): a
    -- deterministic HMAC (never a bare hash, never reversible) that lets a redemption
    -- resolve the ONE candidate row for the presented code and verify a SINGLE Argon2
    -- hash, instead of scanning every unconsumed code (a CPU-amplification lever). It
    -- is NULL for a code RESTORED by the exit-import (issue #58): an export carries
    -- only the one-way hash, never the plaintext, so the index cannot be recomputed;
    -- redemption falls back to scanning only those NULL-index (imported) rows, which
    -- stay bounded by the per-user code count.
    code_bidx      bytea,
    -- The batch this code was minted in; regeneration bumps it and replaces the set.
    generation     integer     NOT NULL DEFAULT 1,
    -- NULL until redeemed; set exactly once at single-use redemption.
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recovery_codes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_codes_scope_idx
    ON recovery_codes (tenant_id, environment_id);
-- Redemption and the remaining-count read scan a subject's codes.
CREATE INDEX recovery_codes_subject_idx
    ON recovery_codes (tenant_id, environment_id, subject, created_at, id);
-- Redemption resolves the ONE candidate by the presented code's blind index (issue
-- #69), so a redemption verifies a single Argon2 hash rather than scanning the set.
CREATE INDEX recovery_codes_bidx_idx
    ON recovery_codes (tenant_id, environment_id, subject, code_bidx);

ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_codes_tenant_isolation ON recovery_codes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane generates a batch (INSERT), reads the unconsumed set for
-- redemption and the remaining count (SELECT), marks one consumed (a COLUMN-scoped
-- UPDATE to consumed_at alone), and clears a prior batch at regeneration (DELETE).
-- COLUMN-scoped UPDATE only (the #31 lesson).
GRANT SELECT, INSERT, DELETE ON recovery_codes TO ironauth_app;
GRANT UPDATE (consumed_at) ON recovery_codes TO ironauth_app;
-- The exit-export surface reads the hashed codes and re-enrolls them under a fresh
-- user (issue #58 covenant): SELECT and INSERT, no more (least privilege).
GRANT SELECT, INSERT ON recovery_codes TO ironauth_control;
