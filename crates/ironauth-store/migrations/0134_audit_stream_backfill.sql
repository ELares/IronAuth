-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Audit stream separation, MIGRATE phase (issue #109).
--
-- 0133 added the nullable column. This file populates the rows written before
-- the split and then closes the column to NULL, so that from here on "which
-- stream is this row in" always has an answer.
--
-- Run this only once the binary that writes `stream` is the one serving. See
-- the note in 0133: tightening the column while an older binary can still
-- INSERT would fail its audit write, and an audit write failing fails the
-- mutation it is transactionally bound to.
--
-- The domain list below is the ONE place a copy of the classification appears
-- in SQL, and it is correct for it to be FROZEN at this version: it classifies
-- only rows written BEFORE this migration ran, whose actions are exactly the
-- actions that existed then. A domain added later needs no backfill, because
-- every row after this point carries the stream its writer computed. The test
-- `the_migration_backfill_lists_only_authentication_domains` parses this list
-- out of this file and checks it against the authentication-stream tables, so
-- the snapshot cannot have been wrong on the day it was taken, and a domain
-- that later leaves the authentication stream fails the build rather than
-- leaving old rows quietly misfiled.

UPDATE audit_log
SET stream = CASE
    WHEN split_part(action, '.', 1) IN (
        'abuse', 'admin_consent', 'attestation', 'auth', 'authorization_code',
        'consent', 'credential', 'device', 'device_code', 'dpop', 'email_otp',
        'external_assertion_issuer', 'external_assertion_subject_mapping',
        'fedcm', 'grant', 'jwt_bearer_assertion', 'login', 'magic_link', 'mfa',
        'passkey', 'password', 'pow', 'pushed_authorization_request',
        'recovery', 'refresh_family', 'refresh_token', 'risk', 'session',
        'sessions', 'signup_quarantine', 'sms_otp', 'step_up', 'sudo', 'token',
        'totp', 'trusted_device', 'webauthn'
    ) THEN 'authentication'
    ELSE 'admin_action'
END
WHERE stream IS NULL;

ALTER TABLE audit_log ALTER COLUMN stream SET NOT NULL;

-- Retention sweeps and stream exports both read (scope, stream, time) in that
-- order. The existing scope index cannot serve them: it would scan every row in
-- the environment and discard the other stream's.
CREATE INDEX audit_log_stream_idx
    ON audit_log (tenant_id, environment_id, stream, occurred_at);
