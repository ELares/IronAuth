-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Hosted lost-password recovery, issue #1479. EXPAND only; no account mutation.
CREATE TABLE password_reset_challenges (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    client_id text NOT NULL CHECK (client_id <> ''),
    browser_binding_hash bytea NOT NULL CHECK (octet_length(browser_binding_hash) = 32),
    authorization_return_to text NOT NULL
        CHECK (octet_length(authorization_return_to) BETWEEN 1 AND 16384),
    -- Unknown/ineligible requests have the same ceremony shape without a subject.
    -- A real binding is indivisible and must be rechecked during completion.
    subject text,
    identifier_id text,
    recipient_revision text,
    recovery_id text,
    credential_digest bytea,
    cancellation_token_digest bytea,
    code_hash text NOT NULL CHECK (octet_length(code_hash) BETWEEN 1 AND 1024),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    -- Actual acceptance of the code and every required owner notification, never
    -- a logging sender invocation. The adapter records one terminal send result.
    delivery_state text NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN ('pending', 'accepted', 'refused', 'uncertain')),
    notified_channels integer NOT NULL DEFAULT 0 CHECK (notified_channels BETWEEN 0 AND 32),
    delivery_finished_at timestamptz,
    -- Durable one-attempt admission, never cleared on timeout or process restart.
    delivery_started_at timestamptz CHECK (delivery_started_at >= created_at),
    CONSTRAINT password_reset_delivery CHECK (
        (delivery_state = 'pending' AND notified_channels = 0 AND delivery_finished_at IS NULL)
        OR
        (delivery_state <> 'pending' AND delivery_finished_at IS NOT NULL
         AND delivery_finished_at >= created_at
         AND (delivery_state <> 'accepted' OR notified_channels > 0))
    ),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'completed', 'cancelled', 'refused')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    finished_at timestamptz,
    -- Keyed request digest and resulting credential-generation digest, never
    -- plaintext password/code or an ordinary SHA digest of a password.
    completion_request_hash bytea,
    completion_credential_digest bytea,
    CONSTRAINT password_reset_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT password_reset_lifetime
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CONSTRAINT password_reset_binding CHECK (
        (subject IS NULL AND identifier_id IS NULL AND recipient_revision IS NULL
         AND recovery_id IS NULL AND credential_digest IS NULL AND cancellation_token_digest IS NULL)
        OR
        (subject IS NOT NULL AND subject <> ''
         AND identifier_id IS NOT NULL AND identifier_id <> ''
         AND recipient_revision IS NOT NULL AND recipient_revision <> ''
         AND recovery_id IS NOT NULL AND recovery_id <> ''
         AND credential_digest IS NOT NULL AND octet_length(credential_digest) = 32
         AND cancellation_token_digest IS NOT NULL AND octet_length(cancellation_token_digest) = 32)
    ),
    CONSTRAINT password_reset_completion CHECK (
        (state = 'pending' AND finished_at IS NULL
         AND completion_request_hash IS NULL AND completion_credential_digest IS NULL)
        OR
        (state IN ('cancelled', 'refused') AND finished_at IS NOT NULL
         AND finished_at >= created_at
         AND completion_request_hash IS NULL AND completion_credential_digest IS NULL)
        OR
        (state = 'completed' AND delivery_state = 'accepted' AND subject IS NOT NULL AND attempt_count > 0
         AND finished_at IS NOT NULL AND finished_at >= created_at
         AND finished_at < expires_at
         AND completion_request_hash IS NOT NULL AND octet_length(completion_request_hash) = 32
         AND completion_credential_digest IS NOT NULL AND octet_length(completion_credential_digest) = 32)
    ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);
CREATE UNIQUE INDEX password_reset_active_subject_idx
    ON password_reset_challenges (tenant_id, environment_id, subject)
    WHERE state = 'pending' AND subject IS NOT NULL;
-- Retain these immutable digests while the associated recovery is pending, even
-- when its short-lived code has expired or been replaced. No plaintext capability.
CREATE UNIQUE INDEX password_reset_cancellation_idx
    ON password_reset_challenges (tenant_id, environment_id, cancellation_token_digest)
    WHERE cancellation_token_digest IS NOT NULL;
CREATE INDEX password_reset_expiry_idx
    ON password_reset_challenges (tenant_id, environment_id, expires_at);
ALTER TABLE password_reset_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY password_reset_challenges_scope ON password_reset_challenges
    USING (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true))
    WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true));
GRANT SELECT, INSERT, DELETE ON password_reset_challenges TO ironauth_app;
GRANT UPDATE (attempt_count, state, finished_at, completion_request_hash,
              completion_credential_digest, delivery_state, notified_channels,
              delivery_finished_at, delivery_started_at) ON password_reset_challenges TO ironauth_app;

-- Persist the policy duration separately from the absolute, notification-anchored
-- horizon. Reusing a case must not mistake mail latency for its required delay.
ALTER TABLE recovery_flows ADD COLUMN password_reset_delay_us bigint
    CHECK (password_reset_delay_us >= 0);
GRANT UPDATE (password_reset_delay_us) ON recovery_flows TO ironauth_app;

-- A terminal owner notification becomes due only after completion or cancellation. The outbox
-- carries its challenge ID, never its code, password, address or cancellation URL.
ALTER TABLE password_reset_challenges
    ADD COLUMN owner_notice_kind text CHECK (owner_notice_kind IN ('completed','cancelled')),
    ADD CONSTRAINT password_reset_notice_kind CHECK (owner_notice_kind IS NULL OR owner_notice_kind=state),
    ADD COLUMN completion_notice_state text NOT NULL DEFAULT 'pending'
        CHECK (completion_notice_state IN ('pending','accepted','refused','uncertain')),
    ADD COLUMN completion_notice_started_at timestamptz,
    ADD COLUMN completion_notice_finished_at timestamptz,
    ADD COLUMN completion_notice_channels integer NOT NULL DEFAULT 0
        CHECK (completion_notice_channels BETWEEN 0 AND 32),
    ADD CONSTRAINT password_reset_notice_claim CHECK (
        completion_notice_started_at IS NULL OR
        (owner_notice_kind IS NOT NULL AND completion_notice_started_at >= finished_at)),
    ADD CONSTRAINT password_reset_notice_result CHECK (
        (completion_notice_state='pending' AND completion_notice_finished_at IS NULL
         AND completion_notice_channels=0)
        OR
        (completion_notice_state<>'pending' AND completion_notice_started_at IS NOT NULL
         AND completion_notice_finished_at IS NOT NULL
         AND completion_notice_finished_at >= completion_notice_started_at
         AND (completion_notice_state<>'accepted' OR completion_notice_channels>0))
    );
GRANT UPDATE (owner_notice_kind,completion_notice_state,completion_notice_started_at,
              completion_notice_finished_at,completion_notice_channels)
    ON password_reset_challenges TO ironauth_app;
