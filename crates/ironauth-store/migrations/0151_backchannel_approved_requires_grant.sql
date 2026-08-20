-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- An approved backchannel request must name the grant its tokens hang off (issue #131),
-- added unvalidated. 0152 validates it.
--
-- Nine rounds of review on the CIBA redemption path found the same family of defect, and
-- every one of them was reachable only through an approved row whose `grant_id` is NULL.
-- The tokens have nothing to hang off, a revocation has nothing to reach, and nothing in
-- the database links the issued tokens back to the `auth_req_id`.
--
-- The code refuses that shape at three places: `decide` will not create it,
-- `approved_details` will not report it as redeemable, and `redeem` and `redeem_approved`
-- will not consume it. This is the fourth, and the only one that survives a writer who has
-- not read any of them. The application role holds table-wide INSERT and column-scoped
-- UPDATE here, and `status` and `grant_id` are INDEPENDENTLY writable in that list, so the
-- data plane can produce the shape with its granted privileges: both an INSERT naming
-- `status = 'approved'` with no grant and an UPDATE moving a pending row across were
-- demonstrated as `ironauth_app` under RLS, and both are refused now.
--
-- Deliberately NOT `NOT NULL`: a pending, denied or expired request has no grant and must
-- not be forced to invent one. The constraint is conditional on the one status where the
-- column is load bearing.
--
-- SPLIT ACROSS TWO FILES, and the reason is the lock rather than taste.
--
-- `/backchannel_authenticate` is a mounted production route (`ciba.rs` calls `create` on
-- every request), and 0147 says of this table "No DELETE: a spent request is invalidated by
-- status, never removed". So it grows with traffic and is never pruned. A VALIDATING
-- `ADD CONSTRAINT` takes AccessExclusiveLock and scans the whole table while holding it, in
-- front of every new reader.
--
-- `lock_timeout` does not help with that, and an earlier version of this header claimed it
-- did. It bounds how long the migration WAITS FOR the lock, never how long it HOLDS it:
-- measured with `lock_timeout = 1s` against a 3.4s scan, a concurrent reader blocked 2.92s,
-- nearly three times the timeout. 0150 makes the same `lock_timeout` argument soundly only
-- because it pairs it with "both tables are small per-environment configuration, so the scan
-- is short". This table is the opposite of that by construction.
--
-- An earlier version also put `ADD ... NOT VALID` and `VALIDATE` in ONE file and claimed the
-- scan then ran under a light lock. That was wrong, and measurably so: `MigrationRunner`
-- wraps each FILE in one transaction, so the AccessExclusiveLock from the ADD is held
-- through the VALIDATE, and a reader blocked 2.95s either way.
--
-- What that same runner loop gives, and what the earlier header wrongly said would need a
-- new runner capability, is one transaction PER FILE. So two files are two transactions:
-- this one takes the heavy lock for an instant and does no scan, and 0152 scans under
-- ShareUpdateExclusiveLock, which blocks neither readers nor writers. Measured: 0.02s for a
-- concurrent reader, against 2.92s for the validating single statement.
--
-- One consequence to know while this file has run and 0152 has not: a violating row is not
-- merely unredeemable but UNPOLLABLE, because `poll` updates `last_poll_at` and Postgres
-- re-checks the constraint on the new row version. There are no violating rows to be found
-- (nothing has ever written an approved row: `decide` is the only writer of that status and
-- has no production caller), so the window is empty in practice, and it is worth naming
-- because "no rows violate" is the reason this is safe and not a reason the lock does not
-- matter. Those are different questions and conflating them is what produced two wrong
-- headers.

-- Bounded rather than unbounded. This is the acquisition wait, which is all `lock_timeout`
-- ever bounds, and here it is all that needs bounding because the statement does no scan.
-- TUNABLE for the reasons 0150 sets out at length; the `nullif` is load bearing there and
-- here.
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
    ADD CONSTRAINT backchannel_authentication_requests_approved_has_grant
    CHECK (status <> 'approved' OR grant_id IS NOT NULL) NOT VALID;
