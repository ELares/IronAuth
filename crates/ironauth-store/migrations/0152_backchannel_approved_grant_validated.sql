-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Validate the constraint 0151 added unvalidated (issue #131).
--
-- A SEPARATE FILE because `MigrationRunner` runs one transaction per file, and that is the
-- whole mechanism: 0151's AccessExclusiveLock is released at its COMMIT, so this scan takes
-- only ShareUpdateExclusiveLock and blocks neither readers nor writers. Putting both
-- statements in one file holds the heavy lock across the scan and buys nothing, which an
-- earlier version of this change did and which was measured: a concurrent reader blocked
-- 2.95s in one file, 0.02s across two.
--
-- `NOT VALID` alone would have been enough for correctness, since Postgres enforces such a
-- constraint on every new row and only skips the back-scan. It is validated anyway because
-- an unvalidated constraint is invisible to the planner and, more to the point here, leaves
-- a permanent "we never checked" in the schema for a table whose whole argument is that the
-- shape must be unrepresentable.

-- Bounded acquisition wait, as in 0151. The scan itself is not bounded by this and does not
-- need to be: it does not block anyone.
DO $$
BEGIN
    PERFORM set_config(
        'lock_timeout',
        coalesce(nullif(current_setting('ironauth.migration_lock_timeout', true), ''), '3s'),
        true
    );
END
$$;

ALTER TABLE backchannel_authentication_requests
    VALIDATE CONSTRAINT backchannel_authentication_requests_approved_has_grant;
