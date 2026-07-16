-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Email OTP codes and scanner-safe magic-link tokens: the passwordless / recovery /
-- address-verification factor state (issue #68).
--
-- This migration lands the two new pieces of persistent state the email-OTP and
-- magic-link factors need, both NEW tenant-scoped tables with forced row-level
-- security:
--
--   1. email_otp_codes: one active numeric code per (user, purpose). The code is a
--      low-entropy 6-8 digit secret the user retypes, so it is stored HASHED with the
--      SAME admission-controlled Argon2id password-hashing pool (issue #62) as a
--      password verifier: code_hash is a one-way PHC string (never a plaintext code,
--      never reversible), so a database dump reveals no usable code. A partial unique
--      index enforces AT MOST ONE active (unconsumed) code per (subject, purpose): a
--      reissue deletes the predecessor and inserts a fresh one, so the prior code is
--      invalidated. attempt_count is a per-code wrong-guess counter; the code dies
--      once it reaches max_attempts. expires_at is the TTL horizon (a per-tenant value
--      inside the 5-10 minute band). The recipient email is PII, so it is NEVER a
--      plaintext column: it is sealed under the scope DEK and blind-indexed (issue
--      #48), exactly like a user identifier.
--
--   2. magic_link_tokens: one active scanner-safe magic-link challenge per (user,
--      purpose). token_digest is the SHA-256 digest of a high-entropy CSPRNG bearer
--      token (the #21/#29 digest-only single-use pattern): the plaintext token is
--      emailed and never stored, and a database dump yields nothing replayable.
--      short_code_hash is the Argon2id PHC (issue #62) of the short cross-device code
--      printed in the same email, so a broken-link email client still completes login.
--      binding_digest is the SHA-256 digest of the same-device binding secret set as a
--      cookie at request time; consumption is bound to the requesting browser (or, when
--      the cookie is absent, to the originating device via the short code). consumed_at
--      is set exactly once (single-use); expires_at is the TTL horizon; purpose binds
--      the link to one flow. The recipient email is sealed and blind-indexed (issue
--      #48). Scanner-safety is a CONSUMPTION-path property (a GET only renders a
--      confirmation page; only a POST flips consumed_at), enforced in the OIDC handler,
--      not the schema; the schema only guarantees single-use and TTL.
--
-- Migration safety obligation (see migrate.rs): both NEW tenant-scoped tables ENABLE
-- and FORCE row-level security, add the (tenant, environment) isolation policy, add the
-- nonempty-scope CHECK, and are registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The email-OTP code store (issue #68).
--
-- id is an `eot_` scoped identifier (embeds its (tenant, environment)), so a code minted
-- in one scope parses as a uniform not-found under another. subject is the `usr_` id the
-- code belongs to; every read and write filters on it (anti-IDOR). code_hash is the
-- Argon2id PHC verifier of the numeric code, minted through the admission-controlled
-- hashing pool (issue #62): one-way, never reversible, never a plaintext column. purpose
-- binds the code to one flow (login, register, mfa, recovery, verify_address); the
-- (subject, purpose) partial unique index over the active rows makes reissue invalidate
-- the predecessor. attempt_count counts wrong guesses; the code dies at max_attempts.
-- expires_at is the TTL horizon; consumed_at is set exactly once at a successful verify.
-- ---------------------------------------------------------------------------
CREATE TABLE email_otp_codes (
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
    -- The recipient email blind index: a deterministic per-tenant keyed HMAC (issue
    -- #48), never the plaintext address, for a scope-safe equality lookup.
    recipient_email_bidx   bytea       NOT NULL,
    -- The recipient email sealed under the scope's active DEK (issue #48), opened only
    -- for an authorized view. Never a plaintext email column.
    recipient_email_sealed bytea       NOT NULL,
    -- The DEK version the recipient email was sealed under (for transparent open).
    pii_dek_version        integer     NOT NULL,
    -- Wrong-guess counter; the code dies once it reaches max_attempts.
    attempt_count          integer     NOT NULL DEFAULT 0,
    -- The per-code wrong-guess budget (a per-tenant value); the code dies at this count.
    max_attempts           integer     NOT NULL DEFAULT 5,
    -- The TTL horizon (a per-tenant value inside the 5-10 minute band).
    expires_at             timestamptz NOT NULL,
    -- NULL until verified; set exactly once at a successful single-use verify.
    consumed_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_otp_codes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed purpose set: an unknown purpose can never be written.
    CONSTRAINT email_otp_codes_purpose_known
        CHECK (purpose IN ('login', 'register', 'mfa', 'recovery', 'verify_address')),
    -- The accepted numeric-code width bound (mirrors the config email_otp_code_digits).
    CONSTRAINT email_otp_codes_attempts_nonneg
        CHECK (attempt_count >= 0 AND max_attempts >= 1),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX email_otp_codes_scope_idx
    ON email_otp_codes (tenant_id, environment_id);
-- The verify path resolves a subject's active code for a purpose.
CREATE INDEX email_otp_codes_subject_idx
    ON email_otp_codes (tenant_id, environment_id, subject, purpose);
-- AT MOST ONE active (unconsumed) code per (subject, purpose): a reissue deletes the
-- predecessor and inserts a fresh row, so the prior code is invalidated. Consumed rows
-- are unconstrained (they are history until pruned).
CREATE UNIQUE INDEX email_otp_codes_active_idx
    ON email_otp_codes (tenant_id, environment_id, subject, purpose)
    WHERE consumed_at IS NULL;

ALTER TABLE email_otp_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_otp_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY email_otp_codes_tenant_isolation ON email_otp_codes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane issues a code (INSERT, after DELETE-ing any prior active one), resolves
-- and verifies it (SELECT), records a wrong guess and marks it consumed (a COLUMN-scoped
-- UPDATE to attempt_count / consumed_at alone), and prunes a predecessor (DELETE).
-- COLUMN-scoped UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON email_otp_codes TO ironauth_app;
GRANT UPDATE (attempt_count, consumed_at) ON email_otp_codes TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The scanner-safe magic-link token store (issue #68).
--
-- id is an `mlk_` scoped identifier and doubles as the routing handle embedded in the
-- link token wire form (`ira_mlk_<id>~<secret>`), so the scope is recoverable from the
-- token without a database hit. subject is the `usr_` id the link belongs to.
-- token_digest is the SHA-256 of the emailed bearer token (issue #29): one-way, the only
-- token material stored, matched by equality on consumption. short_code_hash is the
-- Argon2id PHC (issue #62) of the printed cross-device short code. binding_digest is the
-- SHA-256 of the same-device binding secret set as a cookie at request time. purpose
-- binds the link to one flow. consumed_at is set exactly once (single-use); expires_at is
-- the TTL horizon.
-- ---------------------------------------------------------------------------
CREATE TABLE magic_link_tokens (
    id                     text        PRIMARY KEY,
    tenant_id              text        NOT NULL,
    environment_id         text        NOT NULL,
    -- The end-user subject (a `usr_` id) this link belongs to.
    subject                text        NOT NULL,
    -- The flow this link authorizes (the closed set below).
    purpose                text        NOT NULL,
    -- The SHA-256 digest of the emailed bearer token (issue #29). One-way, the only
    -- token material stored: a database dump yields nothing replayable.
    token_digest           text        NOT NULL,
    -- The Argon2id PHC verifier of the printed cross-device short code (issue #62).
    -- One-way, never a plaintext code.
    short_code_hash        text        NOT NULL,
    -- The SHA-256 digest of the same-device binding secret set as a cookie at request
    -- time. Consumption on the requesting browser matches this; a different device has no
    -- cookie and falls back to the short code entered on the originating device.
    binding_digest         text        NOT NULL,
    -- The recipient email blind index (issue #48), never the plaintext address.
    recipient_email_bidx   bytea       NOT NULL,
    -- The recipient email sealed under the scope's active DEK (issue #48).
    recipient_email_sealed bytea       NOT NULL,
    -- The DEK version the recipient email was sealed under (for transparent open).
    pii_dek_version        integer     NOT NULL,
    -- The TTL horizon (a per-tenant value).
    expires_at             timestamptz NOT NULL,
    -- NULL until consumed; set exactly once at single-use consumption.
    consumed_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT magic_link_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed purpose set: an unknown purpose can never be written.
    CONSTRAINT magic_link_tokens_purpose_known
        CHECK (purpose IN ('login', 'register', 'mfa', 'recovery', 'verify_address')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX magic_link_tokens_scope_idx
    ON magic_link_tokens (tenant_id, environment_id);
-- Consumption resolves the ONE candidate by the presented token's digest within scope.
CREATE UNIQUE INDEX magic_link_tokens_token_idx
    ON magic_link_tokens (tenant_id, environment_id, token_digest);
-- The cross-device short-code path resolves the active link by its binding digest.
CREATE INDEX magic_link_tokens_binding_idx
    ON magic_link_tokens (tenant_id, environment_id, binding_digest)
    WHERE consumed_at IS NULL;
-- AT MOST ONE active (unconsumed) link per (subject, purpose): a reissue deletes the
-- predecessor and inserts a fresh row, so the prior link is invalidated.
CREATE UNIQUE INDEX magic_link_tokens_active_idx
    ON magic_link_tokens (tenant_id, environment_id, subject, purpose)
    WHERE consumed_at IS NULL;

ALTER TABLE magic_link_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_link_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY magic_link_tokens_tenant_isolation ON magic_link_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane issues a link (INSERT, after DELETE-ing any prior active one), renders
-- the confirmation page and resolves the token / binding (SELECT), marks it consumed (a
-- COLUMN-scoped UPDATE to consumed_at alone), and prunes a predecessor (DELETE).
-- COLUMN-scoped UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON magic_link_tokens TO ironauth_app;
GRANT UPDATE (consumed_at) ON magic_link_tokens TO ironauth_app;
