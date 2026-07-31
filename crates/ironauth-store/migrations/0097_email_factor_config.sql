-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The per (tenant, environment) EMAIL-FACTOR configuration: the explicit
-- factor-downgrade opt-in for the email possession family (issue #267).
--
-- Issue #70 shipped `sms_config.allow_factor_downgrade` (migration 0050) as the ONE
-- explicit, per-tenant permission that lets a WEAK possession factor mint a primary
-- login session for an account already protected by a stronger factor (a passkey or an
-- active TOTP). The email possession family (the email OTP of issue #68, the
-- scanner-safe magic link of issue #68, and the headless recovery journey of issue #84,
-- which reuses the SAME email-OTP verify core) had NO such surface at all, so it had no
-- gate either: an actor who controlled a mailbox could mint a primary session over a
-- passkey. This table is the missing surface, shaped EXACTLY like `sms_config` so an
-- operator who has learned one has learned the other.
--
-- ---------------------------------------------------------------------------
-- (1) A scope with NO row is the SAFE default, not an open one.
-- ---------------------------------------------------------------------------
-- The reader (`EmailFactorConfigRepo::config`) resolves a missing row to
-- `EmailFactorConfig::default()`, whose `allow_factor_downgrade` is FALSE. So every
-- environment that exists today, and every environment created later, refuses the
-- downgrade until an operator deliberately turns it on. There is no "enabled" column
-- here: unlike SMS, the email factors are enabled by the DEPLOYMENT configuration
-- (`email_otp_enabled` / `magic_link_enabled`), and this table governs ONLY the
-- downgrade permission. Adding an enablement column would create a second, divergent
-- source of truth for whether the factor is usable.
--
-- ---------------------------------------------------------------------------
-- (2) Why one row for the whole email family rather than one per factor.
-- ---------------------------------------------------------------------------
-- The email OTP, the magic link, and the recovery journey all prove the SAME thing:
-- possession of the mailbox. They sit at the same rung of the credential ladder
-- (`RecoveryFactor::EmailOtp`, issue #81), so a tenant that accepts the downgrade risk
-- for one has accepted it for all three; per-factor rows would let an operator believe
-- they had closed a hole they had only moved. SMS keeps its own column because it is a
-- DIFFERENT recipient channel with its own country allowlist, velocity caps, and
-- pumping defense, and because that column is already shipped and load-bearing.
--
-- ---------------------------------------------------------------------------
-- Migration safety obligation (see migrate.rs).
-- ---------------------------------------------------------------------------
-- The new tenant-scoped table ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy and the nonempty-scope CHECK, and is
-- registered in scripts/query-audit.sh. Every statement is additive, so this migration
-- is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per-scope email-factor configuration.
--
-- The configuration is a per-scope SINGLETON (exactly one row per (tenant,
-- environment)), mirroring sms_config: there is no surrogate id, the scope IS the key,
-- and an upsert collapses onto it.
-- ---------------------------------------------------------------------------
CREATE TABLE email_factor_config (
    tenant_id              text        NOT NULL,
    environment_id         text        NOT NULL,
    -- The explicit downgrade opt-in. FALSE (the default) means an email possession
    -- proof may NOT mint a primary session for an account holding a stronger factor.
    allow_factor_downgrade boolean     NOT NULL DEFAULT false,
    updated_at             timestamptz NOT NULL,
    CONSTRAINT email_factor_config_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    PRIMARY KEY (tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE email_factor_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_factor_config FORCE ROW LEVEL SECURITY;
CREATE POLICY email_factor_config_tenant_isolation ON email_factor_config
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- ---------------------------------------------------------------------------
-- Grants: exactly what ships, and to whom.
-- ---------------------------------------------------------------------------
-- EVERYTHING here goes to ironauth_app, the data-plane role, and NOTHING goes to
-- ironauth_control. Not even SELECT. That is deliberate and is stated plainly because
-- it is the opposite of what a reader would guess from the word "configuration":
--
--   * the READ is a data-plane read. The no-silent-downgrade gate consults this row on
--     every session-establishing email verify, on the request path, through the
--     application pool. That is why ironauth_app holds SELECT.
--   * the WRITE is also issued through the application pool today
--     (ActingEmailFactorConfigRepo, reached from ScopedStore::acting), so INSERT and the
--     column-scoped UPDATE go there too. This mirrors sms_config in migration 0050
--     exactly, which likewise grants the whole surface to ironauth_app and nothing to
--     ironauth_control; the shape is PROPAGATED precedent, not a fresh decision.
--
-- The honest consequence: this table's write privilege is NOT control-plane-confined
-- the way, say, clients.first_party is. Whatever holds an ironauth_app connection can
-- upsert the opt-in as far as the grants are concerned. What actually prevents that
-- today is that no production code path calls the setter at all (see the note on
-- ActingEmailFactorConfigRepo::set_allow_factor_downgrade): the opt-in is unreachable
-- from any surface, so every scope refuses the downgrade. When a management surface
-- lands, moving the write to ironauth_control and adding a management-plane privilege
-- check is that change's job, and this comment is the record of what it inherits.
--
-- What the grants DO confine, and what the #31 least-privilege lesson buys here:
-- COLUMN-scoped UPDATE, so only the opt-in and its timestamp may change and the scope
-- is immutable (a different scope is a different row); and no DELETE at all, so the
-- opt-in is reset by setting it back to false rather than by removing the row, and the
-- audit trail of who turned it on and who turned it off stays continuous.
GRANT SELECT, INSERT ON email_factor_config TO ironauth_app;
GRANT UPDATE (allow_factor_downgrade, updated_at) ON email_factor_config TO ironauth_app;
