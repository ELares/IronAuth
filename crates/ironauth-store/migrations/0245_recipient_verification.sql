-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Subject-bound mailbox verification, issue #1436. EXPAND only.
-- Existing accounts are not inferred to be indexed or verified. The new flow
-- refuses an incompletely indexed scope until a separately controlled backfill.
ALTER TABLE users ADD COLUMN recipient_email_bidx bytea;
ALTER TABLE users ADD COLUMN recipient_email_indexed boolean NOT NULL DEFAULT false;
CREATE INDEX users_recipient_email_idx
    ON users (tenant_id, environment_id, recipient_email_bidx);

CREATE TABLE recipient_verification_challenges (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    subject text NOT NULL,
    recipient_bidx bytea NOT NULL,
    expected_identifier_id text,
    code_hash text NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT recipient_verification_challenges_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);
CREATE UNIQUE INDEX recipient_verification_challenges_active_idx
    ON recipient_verification_challenges (tenant_id, environment_id, subject)
    WHERE consumed_at IS NULL;
ALTER TABLE recipient_verification_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipient_verification_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_verification_challenges_scope ON recipient_verification_challenges
    USING (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true))
    WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true));

CREATE TABLE recipient_email_verifications (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    subject text NOT NULL,
    recipient_bidx bytea NOT NULL,
    identifier_id text NOT NULL,
    revision text NOT NULL,
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, subject),
    UNIQUE (tenant_id, environment_id, recipient_bidx),
    CONSTRAINT recipient_email_verifications_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);
ALTER TABLE recipient_email_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipient_email_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_email_verifications_scope ON recipient_email_verifications
    USING (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true))
    WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true)
       AND environment_id = current_setting('ironauth.environment_id', true));

GRANT SELECT, INSERT, DELETE ON recipient_verification_challenges TO ironauth_app;
GRANT UPDATE (attempt_count, consumed_at) ON recipient_verification_challenges TO ironauth_app;
GRANT SELECT, INSERT ON recipient_email_verifications TO ironauth_app;
GRANT UPDATE (recipient_bidx, identifier_id, revision, verified_at)
    ON recipient_email_verifications TO ironauth_app;
GRANT UPDATE (verified) ON user_identifiers TO ironauth_app;
