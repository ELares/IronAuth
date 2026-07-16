-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Guarded SMS OTP with pumping defense (issue #70).
--
-- SMS OTP is the weakest factor IronAuth ships (NIST SP 800-63B-4 classifies PSTN
-- out-of-band as a RESTRICTED authenticator), so its persistent state encodes the
-- correct posture as the DEFAULT: off in every tenant/environment, country
-- allowlists (never blocklists), hard velocity caps, and send-to-verify conversion
-- telemetry that auto-throttles a pumping route without operator intervention.
--
-- This migration lands four NEW tenant-scoped tables, all with forced row-level
-- security, the (tenant, environment) isolation policy, the nonempty-scope CHECK,
-- and a scripts/query-audit.sh registration. Every statement is additive (an
-- EXPAND):
--
--   1. sms_otp_codes: one active numeric code per (subject, purpose). Semantically
--      IDENTICAL to email_otp_codes (issue #68): a 6-8 digit code is a low-entropy
--      secret, so code_hash is a one-way Argon2id PHC string (issue #62), never a
--      plaintext code; a partial unique index enforces AT MOST ONE active code per
--      (subject, purpose) so a reissue invalidates the predecessor; attempt_count
--      is the per-code wrong-guess budget; expires_at is the TTL horizon. The
--      recipient is a PHONE NUMBER, which is PII, so it is NEVER a plaintext column:
--      it is sealed under the scope DEK and blind-indexed (issue #48), exactly like
--      the email-OTP recipient.
--
--   2. sms_config: the per (tenant, environment) SMS enablement. enabled defaults
--      FALSE, so SMS OTP is off by default in every tenant AND environment; turning
--      it on is an explicit per-tenant action that must ALSO populate the country
--      allowlist below (an empty allowlist means SMS is unusable, not open).
--      allow_factor_downgrade defaults FALSE: the no-silent-downgrade invariant.
--      SMS can never stand in for or reset a passkey/TOTP requirement unless a
--      tenant explicitly opts in here.
--
--   3. sms_country_allowlist: the per (tenant, environment) allowlist of permitted
--      destination country calling codes. This is an ALLOWLIST, not a blocklist: a
--      destination whose country code is absent is refused. An empty allowlist ==
--      SMS unusable.
--
--   4. sms_route_stats: the per (tenant, environment, route) send-to-verify
--      conversion counters and the auto-throttle state. A route is a country/carrier
--      bucket. send_count / verify_count accumulate over a rolling window;
--      throttled_until is set (WITHOUT operator intervention) when conversion drops
--      below the configured threshold over a sufficient sample (the Twilio Fraud
--      Guard insight: healthy routes convert 60-85 percent, under ~30 percent
--      signals pumping). A HEALTHY route is never throttled, so pumping one route
--      never stops the others.

-- ---------------------------------------------------------------------------
-- 1. The SMS-OTP code store (issue #70). Mirrors email_otp_codes (issue #68); the
-- recipient is a sealed + blind-indexed phone number instead of an email.
-- ---------------------------------------------------------------------------
CREATE TABLE sms_otp_codes (
    id                     text        PRIMARY KEY,
    tenant_id              text        NOT NULL,
    environment_id         text        NOT NULL,
    -- The end-user subject (a `usr_` id) this code belongs to.
    subject                text        NOT NULL,
    -- The flow this code authorizes (the closed set below).
    purpose                text        NOT NULL,
    -- The Argon2id PHC verifier of the numeric code (issue #62). One-way, never a
    -- plaintext code: a database dump reveals no usable code.
    code_hash              text        NOT NULL,
    -- The recipient phone blind index: a deterministic per-tenant keyed HMAC (issue
    -- #48), never the plaintext number, for a scope-safe equality lookup.
    recipient_phone_bidx   bytea       NOT NULL,
    -- The recipient phone sealed under the scope's active DEK (issue #48), opened
    -- only for an authorized view. Never a plaintext phone column.
    recipient_phone_sealed bytea       NOT NULL,
    -- The DEK version the recipient phone was sealed under (for transparent open).
    pii_dek_version        integer     NOT NULL,
    -- Wrong-guess counter; the code dies once it reaches max_attempts.
    attempt_count          integer     NOT NULL DEFAULT 0,
    -- The per-code wrong-guess budget (a per-tenant value); the code dies at this count.
    max_attempts           integer     NOT NULL DEFAULT 5,
    -- The TTL horizon (a per-tenant value inside the short SMS band).
    expires_at             timestamptz NOT NULL,
    -- NULL until verified; set exactly once at a successful single-use verify.
    consumed_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sms_otp_codes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT sms_otp_codes_purpose_known
        CHECK (purpose IN ('login', 'register', 'mfa', 'recovery', 'verify_address')),
    CONSTRAINT sms_otp_codes_attempts_nonneg
        CHECK (attempt_count >= 0 AND max_attempts >= 1),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX sms_otp_codes_scope_idx
    ON sms_otp_codes (tenant_id, environment_id);
CREATE INDEX sms_otp_codes_subject_idx
    ON sms_otp_codes (tenant_id, environment_id, subject, purpose);
CREATE UNIQUE INDEX sms_otp_codes_active_idx
    ON sms_otp_codes (tenant_id, environment_id, subject, purpose)
    WHERE consumed_at IS NULL;

ALTER TABLE sms_otp_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_otp_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_otp_codes_tenant_isolation ON sms_otp_codes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- COLUMN-scoped UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON sms_otp_codes TO ironauth_app;
GRANT UPDATE (attempt_count, consumed_at) ON sms_otp_codes TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per (tenant, environment) SMS enablement (issue #70). Off by default.
-- ---------------------------------------------------------------------------
CREATE TABLE sms_config (
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- Off by default in EVERY tenant/environment: SMS OTP is unusable until a tenant
    -- explicitly turns it on AND populates the country allowlist.
    enabled               boolean     NOT NULL DEFAULT false,
    -- The no-silent-downgrade invariant (issue #70): SMS can never bypass or reset a
    -- passkey/TOTP requirement unless a tenant explicitly opts in here. Default false.
    allow_factor_downgrade boolean    NOT NULL DEFAULT false,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, environment_id),
    CONSTRAINT sms_config_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE sms_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_config FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_config_tenant_isolation ON sms_config
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT, INSERT, DELETE ON sms_config TO ironauth_app;
GRANT UPDATE (enabled, allow_factor_downgrade, updated_at) ON sms_config TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. The per (tenant, environment) country ALLOWLIST (issue #70), never a
-- blocklist: a destination whose country calling code is absent is refused.
-- ---------------------------------------------------------------------------
CREATE TABLE sms_country_allowlist (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The E.164 country calling code (for example '1', '44'), digits only.
    country_code    text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, environment_id, country_code),
    CONSTRAINT sms_country_allowlist_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT sms_country_allowlist_code_nonempty
        CHECK (country_code <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX sms_country_allowlist_scope_idx
    ON sms_country_allowlist (tenant_id, environment_id);

ALTER TABLE sms_country_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_country_allowlist FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_country_allowlist_tenant_isolation ON sms_country_allowlist
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT, INSERT, DELETE ON sms_country_allowlist TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 4. The per (tenant, environment, route) send-to-verify conversion counters and
-- auto-throttle state (issue #70). The pumping-defense signal.
-- ---------------------------------------------------------------------------
CREATE TABLE sms_route_stats (
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The route bucket (a country calling code, later country/carrier).
    route_key         text        NOT NULL,
    -- Sends and successful verifications accumulated over the current window.
    send_count        bigint      NOT NULL DEFAULT 0,
    verify_count      bigint      NOT NULL DEFAULT 0,
    -- The rolling conversion window start (the clock seam drives it).
    window_started_at timestamptz NOT NULL DEFAULT now(),
    -- Set (WITHOUT operator intervention) when conversion drops below threshold; a
    -- send to this route is refused until this instant passes. NULL == not throttled.
    throttled_until   timestamptz,
    -- Whether the low-conversion alarm is currently latched for this route.
    alarm_active      boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sms_route_stats_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT sms_route_stats_route_nonempty
        CHECK (route_key <> ''),
    CONSTRAINT sms_route_stats_counts_nonneg
        CHECK (send_count >= 0 AND verify_count >= 0),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX sms_route_stats_scope_idx
    ON sms_route_stats (tenant_id, environment_id);
CREATE UNIQUE INDEX sms_route_stats_route_idx
    ON sms_route_stats (tenant_id, environment_id, route_key);

ALTER TABLE sms_route_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_route_stats FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_route_stats_tenant_isolation ON sms_route_stats
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT, INSERT, DELETE ON sms_route_stats TO ironauth_app;
GRANT UPDATE (send_count, verify_count, window_started_at, throttled_until, alarm_active, updated_at)
    ON sms_route_stats TO ironauth_app;
