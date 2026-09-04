-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0191: where each outbound connection has read to, and how it is doing (issue #137).
--
-- Issue #137 asks for two things this table holds. "Per-app sync state: last cursor, last sync
-- time" is the WORKER's checkpoint, and "health surfaces: per-connection status, error counts
-- and lag (cursor age)" is what an operator reads. They are one row because they are one fact:
-- how far this connection has got, and what happened when it tried.
--
-- WHY NOT COLUMNS ON `scim_push_connections`.
--
-- Two reasons, and the second is the load-bearing one.
--
--   1. 0189 is shipped, and a shipped migration is frozen: its whole file is checksummed, so
--      widening it is not available even if it were the better shape.
--   2. THE GRANTS POINT THE OTHER WAY. A connection is an operator artifact: the control plane
--      writes it and the data plane only reads it. This is the exact inverse -- the worker
--      writes every column here on every poll, and an operator only reads. Putting them in one
--      table would force one of the two planes to hold a write grant it has no business having,
--      and the narrower grant is the whole reason 0189 and 0190 are shaped the way they are.
--
-- WHY A CURSOR IS TEXT AND NOT A NUMBER. `EventCursor` is deliberately opaque (#107): a
-- consumer that stores a bare sequence is invited to compute `cursor + 1`, and a stored integer
-- cannot express a future ordering domain. What survives a restart has to be the WIRE form, so
-- this column holds exactly the string the feed handed over and never interprets it.
--
-- WHY THE PAUSE IS A TIMESTAMP AND NOT A FLAG. #137 says a downstream outage "pauses the cursor
-- rather than dropping events". A boolean would need something to clear it, and the something
-- would be another worker or an operator; a deadline clears itself, so an outage that ends
-- while nobody is looking recovers without an intervention.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it inert.

CREATE TABLE scim_push_sync_state (
    -- The connection IS the key. One connection has exactly one position in the feed, so a
    -- surrogate id would add a way to have two and no way to say which is current.
    connection_id        text        PRIMARY KEY,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,

    -- WHERE THE WORKER HAS READ TO, as the feed's own opaque wire form. NULL means "has never
    -- tailed", which is not the same as "at the beginning": a connection that has not finished
    -- its backfill must not start tailing, and a NULL here is what says so.
    cursor               text,

    -- THE BACKFILL, which #137 requires to be resumable. A connection enumerates everything in
    -- scope before it starts tailing, and a worker killed halfway has to resume rather than
    -- restart: `backfill_after` is the subject id it got to, so the next run continues from
    -- there. A closed vocabulary, so a fourth state is a migration rather than a typo.
    backfill_state       text        NOT NULL DEFAULT 'pending'
                                     CHECK (backfill_state IN ('pending', 'running', 'complete')),
    backfill_after       text,

    -- LAG (issue #137, criterion 2) is a question about EVENT time, not about wall clock at the
    -- worker. Storing when the last processed event was CREATED lets the surface answer "this
    -- connection is four minutes behind the feed" by comparing against the newest event, which
    -- is the number an operator can act on. `last_polled_at` moves on every poll including the
    -- empty ones, so a connection that is idle because nothing happened is distinguishable from
    -- one that is idle because the worker is wedged -- two states a single timestamp conflates.
    last_event_at        timestamptz,
    last_polled_at       timestamptz,
    last_synced_at       timestamptz,

    -- FAILURE STATE. The count is what backoff is computed from and what "error counts" in the
    -- criterion names; the message is what an operator reads. Both are about the CONNECTION
    -- (the downstream is unreachable), which is a different question from 0190's per-resource
    -- errors (this user will not provision), and both questions get asked.
    consecutive_failures integer     NOT NULL DEFAULT 0,
    last_error_at        timestamptz,
    last_error           text,

    -- The outage pause. Until this passes, the worker skips the connection and leaves the
    -- cursor exactly where it is, which is what "pauses rather than drops" means.
    paused_until         timestamptz,

    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_push_sync_state_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- A cursor is either absent or a real position. An EMPTY string would round-trip through
    -- the wire decoder as a malformed value at the worst possible moment: on the restart after
    -- a crash, which is the one time the checkpoint matters.
    CONSTRAINT scim_push_sync_state_cursor_shaped
        CHECK (cursor IS NULL OR (cursor <> '' AND octet_length(cursor) <= 512)),
    CONSTRAINT scim_push_sync_state_backfill_after_shaped
        CHECK (backfill_after IS NULL OR (backfill_after <> '' AND octet_length(backfill_after) <= 512)),
    -- OCTET_LENGTH, matching 0190's bound and its reason: the surface that refuses a message
    -- first counts BYTES, and two bounds on one value that disagree on the unit make one of
    -- them unreachable and the other a 500.
    CONSTRAINT scim_push_sync_state_last_error_bounded
        CHECK (last_error IS NULL OR octet_length(last_error) <= 2048),
    -- A count cannot run backwards. Without this a decrementing bug produces a NEGATIVE backoff
    -- exponent, and the worker hammers a downstream that is already failing.
    CONSTRAINT scim_push_sync_state_failures_nonnegative
        CHECK (consecutive_failures >= 0),
    -- A connection cannot be tailing before its backfill is done. This is the invariant the
    -- NULL cursor above is FOR, written down so it is enforced rather than remembered: pushing
    -- events for a connection that has not enumerated its scope means the first event for an
    -- unprovisioned user creates a resource the backfill then duplicates.
    CONSTRAINT scim_push_sync_state_no_tailing_before_backfill
        CHECK (cursor IS NULL OR backfill_state = 'complete'),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- CASCADE for 0190's reason: `scim_push_connections` is hard deleted, so a key without one
    -- would break that delete with a 23503 the first time a connection had ever run. A position
    -- in the feed for a connection that no longer exists is also meaningless on the merits.
    FOREIGN KEY (connection_id) REFERENCES scim_push_connections (id) ON DELETE CASCADE
);

-- THE WORKER'S OWN QUERY: which connections in this scope are due to run.
--
-- NOT PARTIAL, and the first draft's `WHERE paused_until IS NULL` was a real defect rather than a
-- tuning choice. A pause here is a self-clearing DEADLINE, so the due query is
-- `paused_until IS NULL OR paused_until <= now()`; an index that only holds the rows where the
-- column is NULL can never serve the second half of that. A connection whose outage had ENDED was
-- therefore excluded from the index for ever, which is the exact opposite of the recovery
-- property the column was chosen for.
--
-- `paused_until` leads so the planner can range-scan the expired ones, with `last_polled_at`
-- after it to order the work.
CREATE INDEX scim_push_sync_state_due
    ON scim_push_sync_state (tenant_id, environment_id, paused_until, last_polled_at);

ALTER TABLE scim_push_sync_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_push_sync_state FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_push_sync_state_scope ON scim_push_sync_state
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns this outright, which is the inverse of 0189 and the reason this is its own
-- table: every column the worker maintains is written by the worker, not by an operator.
-- ("Every column" would be false, and the GRANT below says so: the scope columns and
-- `connection_id` are set once at INSERT and are deliberately absent from the UPDATE list.)
--
-- The UPDATE is column-scoped anyway, and the columns left out are the ones that would let a bug
-- move a row between scopes or between connections: `connection_id`, `tenant_id` and
-- `environment_id` are set at INSERT and never again. Re-pointing a checkpoint at another
-- connection would make one connection resume from another's position, which loses events
-- silently rather than loudly.
GRANT SELECT, INSERT ON scim_push_sync_state TO ironauth_app;
GRANT UPDATE (cursor, backfill_state, backfill_after, last_event_at, last_polled_at,
              last_synced_at, consecutive_failures, last_error_at, last_error, paused_until,
              updated_at)
    ON scim_push_sync_state TO ironauth_app;

-- The CONTROL plane reads: criterion 2's health surface is a management route, and it answers
-- from exactly these columns. A SELECT confers no ability to move a cursor.
GRANT SELECT ON scim_push_sync_state TO ironauth_control;

COMMENT ON TABLE scim_push_sync_state IS
    'Issue #137: one row per outbound connection holding its feed position, backfill progress '
    'and health, written by the sync worker and read by the management health surface.';
COMMENT ON COLUMN scim_push_sync_state.cursor IS
    'Issue #137: the event feed''s OPAQUE wire cursor, stored verbatim and never interpreted. '
    'NULL means the connection has not started tailing. The CHECK ties the other direction: a '
    'NON-NULL cursor requires a completed backfill, so a connection cannot tail while it is '
    'still enumerating.';
COMMENT ON COLUMN scim_push_sync_state.paused_until IS
    'Issue #137: a downstream outage pauses the cursor rather than dropping events. A deadline '
    'rather than a flag, so an outage that ends unattended recovers without an intervention.';
