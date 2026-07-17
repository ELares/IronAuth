-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Account recovery as a first-class subsystem (issue #81).
--
-- Recovery is the weakest link in authentication: an attacker who cannot beat a
-- passkey files a recovery request, and in most products recovery quietly bypasses
-- or removes the strongest factor with less scrutiny than a normal login. IronAuth
-- models recovery as a DISTINCT, first-class state machine (not a branch of password
-- reset) governed by three pillars: DELAY as a security feature, NOTIFICATION on
-- every registered channel, and the invariant that recovery can NEVER silently
-- remove a factor STRONGER than the one used to recover.
--
-- This migration lands ONE new tenant-scoped table with forced row-level security:
--
--   recovery_flows: one row per recovery request. It holds:
--     - a scope-embedded `rcv_` id (embeds its (tenant, environment) so a flow
--       minted in one scope parses as a uniform not-found under another);
--     - subject: the `usr_` id the recovery targets. Every read and write filters
--       on it (the anti-IDOR contract);
--     - state: the recovery state machine position, a closed set
--       (initiated / held / cancelled / completed). A recovery that would REDUCE
--       account security is `held` for the configured delay before it can complete;
--     - entry_point: what was lost, a closed set (lost_password /
--       lost_second_factor / lost_all_factors);
--     - recover_acr: the achieved `acr` (the issue #66 credential-ladder strength)
--       of the factor the recovery was performed with. The downgrade invariant
--       compares a later factor removal against THIS strength: removing a factor
--       stronger than `recover_acr` needs the delay elapsed OR a fresh
--       equal-or-stronger re-verification;
--     - cancel_token_digest: the SHA-256 DIGEST of the high-entropy cancellation
--       token carried in the notification link (never the token itself, so a
--       database dump reveals no usable cancellation secret). A presented token is
--       validated by hashing it and matching this digest;
--     - recipient_sealed: the recipient/channel that initiated recovery, SEALED
--       under the scope's envelope DEK (issue #48) since it is end-user PII;
--       pii_dek_version records the DEK it was sealed under, for transparent open
--       on the account export (issue #58);
--     - initiated_at: when the flow began (from the env clock seam, never the DB
--       clock, so the delay/cooldown timers are deterministic under a test clock);
--     - hold_until: the delay-window horizon a downgrade-reducing recovery is HELD
--       until, cancellable throughout. NULL when no delay applies;
--     - cancelled_at / cancel_reason: set exactly once when the flow is cancelled
--       (from a notification link, or superseded by a newer request). A cancelled
--       flow can never complete;
--     - completed_at: set exactly once when the recovery completes.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- ENABLES and FORCES row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- The recovery-flow state machine (issue #81).
--
-- id is a `rcv_` scoped identifier (embeds its (tenant, environment)). subject is
-- the `usr_` id the recovery targets; every read and write filters on it (anti-IDOR).
-- state / entry_point are closed sets pinned by CHECK. recover_acr is the strength
-- context the downgrade invariant compares against. cancel_token_digest is the
-- SHA-256 digest of the notification-link cancellation token (server-side state,
-- never the token). recipient_sealed is sealed under the scope's active DEK (issue
-- #48); pii_dek_version records that DEK. hold_until is the delay-window horizon.
CREATE TABLE recovery_flows (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The end-user subject (a `usr_` id) this recovery targets.
    subject             text        NOT NULL,
    -- The recovery state-machine position (issue #81): a closed set. A recovery that
    -- would REDUCE account security is `held` for the configured delay before it can
    -- complete, cancellable throughout the window.
    state               text        NOT NULL,
    -- What the user lost (issue #81): a closed set of entry points.
    entry_point         text        NOT NULL,
    -- The achieved acr (the issue #66 credential-ladder strength) of the factor the
    -- recovery was performed with. The downgrade invariant compares a factor removal
    -- against this: removing a factor STRONGER than this needs the delay elapsed OR a
    -- fresh equal-or-stronger re-verification.
    recover_acr         text        NOT NULL,
    -- The SHA-256 digest of the high-entropy cancellation token carried in the
    -- notification link (issue #81): server-side state, never the token itself. A
    -- presented token is validated by hashing it to this digest.
    cancel_token_digest bytea       NOT NULL,
    -- The recipient/channel that initiated recovery, sealed under the scope's DEK
    -- (issue #48). End-user PII: never a plaintext column.
    recipient_sealed    bytea       NOT NULL,
    -- The DEK version the recipient was sealed under.
    pii_dek_version     integer     NOT NULL,
    -- When the recovery began, from the env clock seam (deterministic under a test
    -- clock), so the delay and cooldown timers are reproducible.
    initiated_at        timestamptz NOT NULL DEFAULT now(),
    -- The delay-window horizon a downgrade-reducing recovery is HELD until (issue
    -- #81), cancellable throughout. NULL when no delay applies.
    hold_until          timestamptz,
    -- Set exactly once when the flow is cancelled (from a notification link, or
    -- superseded). A cancelled flow can never complete.
    cancelled_at        timestamptz,
    -- The closed cancellation reason (audit / UI legibility).
    cancel_reason       text,
    -- Set exactly once when the recovery completes.
    completed_at        timestamptz,
    CONSTRAINT recovery_flows_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed recovery-state set: an unknown state can never be written.
    CONSTRAINT recovery_flows_state_known
        CHECK (state IN ('initiated', 'held', 'cancelled', 'completed')),
    -- The closed entry-point set: an unknown entry point can never be written.
    CONSTRAINT recovery_flows_entry_point_known
        CHECK (entry_point IN ('lost_password', 'lost_second_factor', 'lost_all_factors')),
    -- The closed cancel-reason set: the reason is present exactly when the flow is
    -- cancelled, and only a known reason can be written.
    CONSTRAINT recovery_flows_cancel_reason_known
        CHECK (
            (cancelled_at IS NULL AND cancel_reason IS NULL)
            OR (cancelled_at IS NOT NULL AND cancel_reason IN (
                'user_notification', 'superseded'
            ))
        ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_flows_scope_idx
    ON recovery_flows (tenant_id, environment_id);
-- The cooldown check and the account export read a subject's rows ordered by
-- (initiated_at, id).
CREATE INDEX recovery_flows_subject_idx
    ON recovery_flows (tenant_id, environment_id, subject, initiated_at, id);
-- A presented cancellation token resolves the ONE candidate flow by its token digest
-- (issue #81), so cancellation checks a single row rather than scanning.
CREATE UNIQUE INDEX recovery_flows_cancel_digest_idx
    ON recovery_flows (tenant_id, environment_id, cancel_token_digest);

ALTER TABLE recovery_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_flows_tenant_isolation ON recovery_flows
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane initiates a flow (INSERT), reads it for cooldown / cancellation /
-- completion (SELECT), and advances its state machine (a COLUMN-scoped UPDATE to the
-- state and lifecycle columns only). COLUMN-scoped UPDATE only (the #31
-- least-privilege lesson): the id, subject, digest, and sealed recipient are
-- immutable once written.
GRANT SELECT, INSERT ON recovery_flows TO ironauth_app;
GRANT UPDATE (state, hold_until, cancelled_at, cancel_reason, completed_at)
    ON recovery_flows TO ironauth_app;
-- The exit-export surface reads the sealed recipient for the account export (issue
-- #58 covenant): SELECT and INSERT, no more (least privilege, mirroring 0053).
GRANT SELECT, INSERT ON recovery_flows TO ironauth_control;
