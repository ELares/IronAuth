-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0192: the grant 0189 said would arrive with the worker, and the two columns it did not foresee.
--
-- 0189 shipped `cursor_sequence`, `backfill_state`, `backfill_after_*`, `backfill_from_sequence`
-- and the health columns on `scim_push_connections`, and said in terms what should happen next:
--
--     `cursor_sequence`, `backfill_*` and the health columns are NOT here [in the grant list].
--     They are the worker's, the worker runs on the data plane, and it does not exist yet: the
--     grant that lets it advance its own cursor belongs in the migration that adds it.
--
-- This is that migration. The worker exists now, so the grant arrives with it.
--
-- WHY THIS EXISTS AT ALL, WHICH IS A CORRECTION RATHER THAN A PLAN.
--
-- 0191 added `scim_push_sync_state`: a second table holding a cursor, a backfill state, an error
-- message and a failure count, all of which 0189 already had. The argument written into 0191 was
-- that the grants point the other way (an operator owns the connection, the worker owns the
-- position), and 0189 had already answered it on the line above the one that should have been
-- read: the split is a GRANT, not a table. 0193 removes the duplicate; this migration makes
-- 0189's columns usable so that removal costs nothing.
--
-- 0189's shape is also the better one, which is worth recording so it is not re-litigated:
--
--   * `backfill_state` is ('pending', 'users', 'groups', 'done'), so it says WHICH collection is
--     being enumerated. 0191's ('pending', 'running', 'complete') cannot express that, and a
--     backfill that has finished users but not groups is a state an operator asks about.
--   * `backfill_after_created_at` + `backfill_after_id` is a composite resume point that matches
--     how every listing in this schema pages. 0191 carried a single opaque string.
--   * `backfill_from_sequence` is documented there as "the newest sequence visible BEFORE the
--     backfill began. Captured first and applied last, so an event that lands mid-backfill is
--     replayed rather than skipped" -- the exact property the worker needs, already designed.
--
-- WHAT 0189 GENUINELY LACKED are the two columns below. Both came out of building the worker,
-- and neither duplicates anything.

-- WHEN THE WORKER LAST LOOKED, including the polls that found nothing.
--
-- `last_success_at` moves only when something was written downstream, so a connection whose feed
-- is simply quiet is indistinguishable from one whose worker is wedged: both sit at an old
-- success time. Separating the two is what lets the health surface say "healthy, nothing to do"
-- rather than "four hours behind".
ALTER TABLE scim_push_connections ADD COLUMN last_polled_at timestamptz;

-- THE OUTAGE PAUSE, as a self-clearing DEADLINE rather than a flag.
--
-- #137 says a downstream outage pauses the cursor rather than dropping events. A boolean would
-- need something to clear it and the something would be another worker or an operator; a deadline
-- clears itself, so an outage that ends while nobody is looking recovers without an intervention.
ALTER TABLE scim_push_connections ADD COLUMN paused_until timestamptz;

-- THE GRANT 0189 DEFERRED. Column-scoped to exactly what the worker writes: the cursor, the
-- backfill progress, and the health columns.
--
-- Everything an OPERATOR owns is absent. `base_url`, `credential_secret_name`,
-- `attribute_mapping`, the scope filters, `write_mode` and `deletion_policy` are configuration,
-- and a worker that could rewrite them could point a live connection at a different downstream.
-- `active` is absent for the same reason and is the control plane's, which 0189 already granted.
-- `organization_id` and the scope columns are absent because a row that could move between
-- organizations is a cross-tenant write waiting to happen.
GRANT UPDATE (
    cursor_sequence,
    backfill_state,
    backfill_after_created_at,
    backfill_after_id,
    backfill_from_sequence,
    last_success_at,
    last_error_at,
    last_error,
    consecutive_failures,
    last_polled_at,
    paused_until,
    updated_at
) ON scim_push_connections TO ironauth_app;

-- THE WORKER'S DUE QUERY: which connections in this scope are ready to run.
--
-- NOT PARTIAL on `paused_until IS NULL`. The due predicate is `paused_until IS NULL OR
-- paused_until <= now()`, and an index holding only the NULL rows can never serve the second
-- half, so a connection whose outage had ENDED would be excluded from it for ever. 0191 shipped
-- exactly that mistake and its review caught it; the correction travels here with the column.
CREATE INDEX scim_push_connections_due
    ON scim_push_connections (tenant_id, environment_id, paused_until, last_polled_at)
    WHERE active;

-- A cursor and a backfill cannot both be live: a connection that is still enumerating must not
-- be tailing, or the first event for an unprovisioned subject creates a resource the backfill
-- then creates again. 0191 stated this as a CHECK and it is the one invariant worth carrying
-- across, because it is the one that produces a duplicate.
ALTER TABLE scim_push_connections
    ADD CONSTRAINT scim_push_connections_no_tailing_before_backfill
    CHECK (cursor_sequence IS NULL OR backfill_state = 'done');

COMMENT ON COLUMN scim_push_connections.last_polled_at IS
    'Issue #137: when the worker last looked, including empty polls. Distinct from '
    'last_success_at so a quiet feed is distinguishable from a wedged worker.';
COMMENT ON COLUMN scim_push_connections.paused_until IS
    'Issue #137: an outage pauses the cursor rather than dropping events. A deadline rather than '
    'a flag, so an outage that ends unattended recovers without an intervention.';
