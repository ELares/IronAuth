-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The durable session-ended fan-out outbox (issue #35).
--
-- The field's most-reported logout gap is not a missing endpoint but missing
-- PROPAGATION: a session ends (a logout, an admin revoke, a bulk revoke, a
-- revoke-everything-for-a-user, a different subject replacing a browser session) and
-- no signal reaches the relying parties, so their sessions silently outlive the OP
-- session. The fix is architectural: ONE internal session-ended event, produced by
-- EVERY terminal end, written in the SAME transaction as the state change, drained by
-- the back-channel logout worker (#34) and the external webhooks (M11) off ONE seam.
--
-- This migration lands that seam as a TRANSACTIONAL OUTBOX. A row is enqueued here in
-- the exact transaction that flips the session (see revoke_session_in_tx and
-- revoke_all_for_user in repository.rs), so an event is never emitted for a
-- rolled-back revoke and never lost for a committed one: the outbox row and the
-- session revocation commit together or not at all, exactly as the audit row does.
--
-- A ROTATION is NOT a session end. The rotation path re-points a session's lineage
-- onto its successor and never enqueues here; only a TERMINAL end (the causes above)
-- produces a row. A naive consumer draining this table therefore never logs a user
-- out on a mere re-authentication.
--
-- Delivery is at-least-once. The enqueue is exactly-once by construction (a session
-- flips at most once, guarded by `revoked_at IS NULL AND ended_at IS NULL`, and the
-- UNIQUE (scope, session_id) below makes a second row for the same session
-- impossible), but a DRAINING consumer may claim a row, act, and crash before marking
-- it delivered, so it re-appears after its lease lapses. Consumers MUST therefore be
-- idempotent (dedup on the event `id`), which is why replaying an event double-revokes
-- nothing and double-sends no logout token.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (session_ended_events) ENABLEs and FORCEs row-level security, adds the (tenant,
-- environment) isolation policy, adds the nonempty-scope CHECK, uses COLUMN-scoped
-- grants (never a table-wide UPDATE, the #31 lesson), and is registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The session-ended outbox.
--
-- id is an sev_ scoped identifier (embeds its (tenant, environment)) and is the
-- IDEMPOTENCY KEY a consumer dedups redelivery on. `sequence` is a monotonic
-- database-assigned ordering key, so a consumer drains in the order sessions ended
-- (a total order globally, and the correct sub-order within one scope). session_id is
-- the SSO session (ses_) that ended; subject is the user (usr_) whose session it was;
-- cause is the terminal end cause (revoked, bulk_revoked, user_revoked_all,
-- logged_out, replaced_by_other_subject), never `rotated` (a rotation is not an end).
-- actor_kind / actor_id attribute the end to the principal that caused it (an admin, a
-- service, the user), copied from the same acting context the audit row carries.
-- correlation_id ties the event back to the request. occurred_at is the end instant,
-- from the application clock seam (never the database clock), so it is deterministic
-- under a manual clock in tests.
--
-- claimed_at and delivered_at are the ONLY columns a draining consumer mutates, and
-- the ONLY columns it is granted UPDATE on: claimed_at is the visibility lease a
-- claim stamps (so a second worker skips a row in flight, and a crashed worker's row
-- reappears once the lease lapses), and delivered_at is the terminal marker a consumer
-- sets once it has durably handled the event. Neither is ever set at enqueue.
CREATE TABLE session_ended_events (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- Database-assigned monotonic drain order (never client-supplied).
    sequence       bigint      GENERATED ALWAYS AS IDENTITY,
    -- The SSO session (a ses_ id) that TERMINALLY ended.
    session_id     text        NOT NULL,
    -- The user (a usr_ id) whose session ended.
    subject        text        NOT NULL,
    -- The terminal end cause. Never `rotated`: a rotation is not a session end.
    cause          text        NOT NULL,
    -- The principal that caused the end (mirrors the audit envelope's actor columns).
    actor_kind     text        NOT NULL,
    actor_id       text        NOT NULL,
    -- The request the end belongs to.
    correlation_id text        NOT NULL,
    -- The end instant, from the application clock seam (deterministic under test).
    occurred_at    timestamptz NOT NULL,
    -- The visibility lease a claim stamps; NULL until first claimed.
    claimed_at     timestamptz,
    -- The terminal delivered marker a consumer sets; NULL until delivered.
    delivered_at   timestamptz,
    CONSTRAINT session_ended_events_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Enqueue idempotency, made structural: a session ends at most once, so it has at
    -- most one session-ended event. A second enqueue for the same session is a bug,
    -- and this makes it fail loudly rather than double-fan-out.
    UNIQUE (tenant_id, environment_id, session_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the ended session must exist in the
    -- SAME tenant and environment.
    FOREIGN KEY (session_id, tenant_id, environment_id)
        REFERENCES sessions (id, tenant_id, environment_id)
);

CREATE INDEX session_ended_events_scope_idx
    ON session_ended_events (tenant_id, environment_id);
-- The drain path: undelivered rows in scope, in sequence order. A partial index keeps
-- the working set to the not-yet-delivered tail rather than the whole history.
CREATE INDEX session_ended_events_undelivered_idx
    ON session_ended_events (tenant_id, environment_id, sequence)
    WHERE delivered_at IS NULL;

ALTER TABLE session_ended_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_ended_events FORCE ROW LEVEL SECURITY;
CREATE POLICY session_ended_events_tenant_isolation ON session_ended_events
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data-plane role ENQUEUEs an event inside the session-revoke transaction (a
-- logout, an RFC 7009 revoke, and the fleet-ops revoke surfaces all run on the data
-- plane), READs the outbox to drain it, and marks a row CLAIMED then DELIVERED. It is
-- granted UPDATE only on the two lifecycle columns a drain touches, NEVER a table-wide
-- UPDATE (which would silently cover every future column, the #31 lesson): the event
-- body (cause, subject, actor, occurred_at) is immutable once enqueued.
GRANT SELECT, INSERT ON session_ended_events TO ironauth_app;
GRANT UPDATE (claimed_at, delivered_at) ON session_ended_events TO ironauth_app;

-- The control-plane role can ENQUEUE too: a future control-plane session-ending path
-- (mirroring the fleet-ops session UPDATE grants migration 0022 already gave it) must
-- be able to write the event in its own transaction, or it would be a bypass of the
-- single choke point. It does not drain, so it gets no UPDATE.
GRANT SELECT, INSERT ON session_ended_events TO ironauth_control;
