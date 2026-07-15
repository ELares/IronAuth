-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Back-Channel Logout registration and the per-RP delivery queue (issue #34).
--
-- OpenID Connect Back-Channel Logout 1.0 is the ONE logout-propagation mechanism that
-- survived third-party-cookie deprecation: when an SSO session ends the OP POSTs a
-- signed Logout Token to each participating relying party's registered
-- backchannel_logout_uri, out of band of any browser. This migration lands the two
-- pieces that surface needs on top of the #35 session-ended outbox (which already tells
-- the worker "a session ended, fan out"):
--
--   1. The client REGISTRATION columns: backchannel_logout_uri (the RP-controlled URL a
--      logout token is POSTed to; only a client that registered one is a participant)
--      and backchannel_logout_session_required (whether the RP requires a `sid` in the
--      token; this OP is session-based and always sends one, so the flag is recorded for
--      completeness rather than acted on).
--
--   2. The per-RP delivery queue (backchannel_logout_deliveries): the #35 outbox is
--      per-SESSION-EVENT and is SHARED by every consumer (this worker AND the M11
--      webhooks), so it cannot carry THIS consumer's per-recipient retry state. The
--      worker therefore EXPLODES one drained session-ended event into one delivery row
--      per participating RP and then marks the outbox event delivered; this table is the
--      at-least-once, per-RP work queue with its own attempts / backoff / dead-letter
--      state, so a slow or failing RP never wedges the others or the outbox.
--
-- Delivery is at-least-once and the RP dedups on the token `jti`. A claim leases a row
-- (claimed_at), a lapsed lease reappears it (a crashed worker re-delivers), and a
-- terminal state (delivered_at set, or dead_lettered_at set after the attempts cap)
-- retires it. next_attempt_at is the backoff gate, always written from the application
-- clock seam (never the database clock) so the schedule is deterministic under a manual
-- clock in tests.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (backchannel_logout_deliveries) ENABLEs and FORCEs row-level security, adds the
-- (tenant, environment) isolation policy, adds the nonempty-scope CHECK, uses
-- COLUMN-scoped grants (never a table-wide UPDATE, the #31 lesson), and is registered in
-- scripts/query-audit.sh. The clients ALTERs are additive (a nullable column and a
-- defaulted boolean), safe for the old binary to ignore. Every statement is additive, so
-- this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The client back-channel-logout registration columns (additive, old-binary safe).
--
-- backchannel_logout_uri defaults to NULL: a client created before this migration (and
-- one that registers no URI) is NOT a back-channel participant, so no logout token is
-- ever built or sent for it. backchannel_logout_session_required defaults to false, the
-- OIDC-registration default.
ALTER TABLE clients
    ADD COLUMN backchannel_logout_uri              text,
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;

-- Column-scoped data-plane write grant (issue #31 lesson, NEVER a table-wide UPDATE).
-- Client registration writes these two columns on the data plane, exactly as the #33
-- post_logout_redirect_uris column-scoped grant does; a table-level UPDATE would
-- auto-cover every future column, so a new column stays app-unwritable until deliberately
-- granted.
GRANT UPDATE (backchannel_logout_uri, backchannel_logout_session_required)
    ON clients TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per-RP back-channel-logout delivery queue.
--
-- id is a `bld_` scoped identifier (embeds its (tenant, environment)). event_id is the
-- `sev_` session-ended outbox row this delivery was exploded from; (event_id, client_id)
-- is UNIQUE within scope, so re-draining the same outbox event (a lease lapse before the
-- worker marked it delivered) re-explodes idempotently rather than double-queuing. sid is
-- the per-(client, session) `sid` value THIS RP's logout token carries: resolved from
-- client_sessions at explode time, so an RP only ever learns its OWN sid, never another
-- client's. logout_uri is the RP's registered backchannel_logout_uri, snapshotted at
-- explode time so a later re-registration cannot retarget an in-flight delivery.
--
-- attempts counts the delivery tries so far; next_attempt_at is the backoff gate (the
-- row is eligible only once now >= next_attempt_at), set from the application clock seam;
-- claimed_at is the in-flight visibility lease; last_error records the most recent
-- failure reason for operator visibility; delivered_at and dead_lettered_at are the two
-- terminal markers (delivered on a 2xx, dead-lettered once attempts hits the cap). These
-- six are the ONLY columns the draining worker mutates, and the ONLY ones it is granted
-- UPDATE on.
CREATE TABLE backchannel_logout_deliveries (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The `sev_` session-ended outbox event this delivery was exploded from.
    event_id       text        NOT NULL,
    -- The SSO session (a `ses_` id) that ended.
    session_id     text        NOT NULL,
    -- The participating OAuth client this token targets.
    client_id      text        NOT NULL,
    -- The per-(client, session) `sid` THIS RP's logout token carries (never another
    -- client's sid).
    sid            text        NOT NULL,
    -- The RP's registered backchannel_logout_uri, snapshotted at explode time.
    logout_uri     text        NOT NULL,
    -- The Logout Token `jti`, assigned ONCE at explode time and reused across every
    -- delivery ATTEMPT of this row. At-least-once delivery re-POSTs the SAME token, so the
    -- jti is stable and the RP dedups a retry on it (a fresh jti per attempt would defeat
    -- that dedup). Part of the immutable delivery body, so it lives under SELECT + INSERT,
    -- never the column-scoped UPDATE grant.
    jti            text        NOT NULL,
    -- The number of delivery attempts so far (the attempts cap dead-letters the row).
    attempts       integer     NOT NULL DEFAULT 0,
    -- The backoff gate: the row is eligible only once now >= next_attempt_at. Written
    -- from the application clock seam (deterministic under a manual clock in tests).
    next_attempt_at timestamptz NOT NULL,
    -- The in-flight visibility lease a claim stamps; NULL until first claimed.
    claimed_at     timestamptz,
    -- The most recent failure reason (a bounded, non-secret label), for operator
    -- visibility; NULL until the first failure.
    last_error     text,
    -- The terminal delivered marker a 2xx sets; NULL until delivered.
    delivered_at   timestamptz,
    -- The terminal give-up marker set once attempts reaches the cap; NULL until then.
    dead_lettered_at timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT backchannel_logout_deliveries_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Idempotent explode: one delivery per (outbox event, client). A second explode of
    -- the same event (a redelivered outbox row) is a no-op via ON CONFLICT DO NOTHING.
    UNIQUE (tenant_id, environment_id, event_id, client_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the ended session must exist in the SAME
    -- tenant and environment.
    FOREIGN KEY (session_id, tenant_id, environment_id)
        REFERENCES sessions (id, tenant_id, environment_id)
);

CREATE INDEX backchannel_logout_deliveries_scope_idx
    ON backchannel_logout_deliveries (tenant_id, environment_id);
-- The drain path: the not-yet-terminal deliveries in scope that are due, oldest gate
-- first. A partial index keeps the working set to the still-pending rows.
CREATE INDEX backchannel_logout_deliveries_due_idx
    ON backchannel_logout_deliveries (tenant_id, environment_id, next_attempt_at)
    WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;

ALTER TABLE backchannel_logout_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE backchannel_logout_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY backchannel_logout_deliveries_tenant_isolation ON backchannel_logout_deliveries
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data-plane role EXPLODES an outbox event into delivery rows (INSERT), READs the
-- queue to drain it, and mutates ONLY the delivery-lifecycle columns: the attempts
-- counter, the backoff gate, the lease, the last-error label, and the two terminal
-- markers. It is NEVER granted a table-wide UPDATE (the #31 lesson): the delivery body
-- (event_id, session_id, client_id, sid, logout_uri, jti) is immutable once exploded.
GRANT SELECT, INSERT ON backchannel_logout_deliveries TO ironauth_app;
GRANT UPDATE (attempts, next_attempt_at, claimed_at, last_error, delivered_at,
              dead_lettered_at)
    ON backchannel_logout_deliveries TO ironauth_app;

-- The control-plane role can READ the queue so a management status surface can report a
-- delivery's state (delivered / retrying / dead-lettered, with its last error). It does
-- not drain, so it gets no UPDATE.
GRANT SELECT ON backchannel_logout_deliveries TO ironauth_control;
