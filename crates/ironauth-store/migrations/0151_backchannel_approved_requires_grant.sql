-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- An approved backchannel request must name the grant its tokens hang off (issue #131).
--
-- Eight rounds of review on the CIBA redemption path found the same family of defect, and
-- every one of them was reachable only through an approved row whose `grant_id` is NULL.
-- The tokens have nothing to hang off, a revocation has nothing to reach, and nothing in
-- the database links the issued tokens back to the `auth_req_id`.
--
-- The code refuses that shape at three places: `decide` will not create it,
-- `approved_details` will not report it as redeemable, and `redeem` and `redeem_approved`
-- will not consume it. This is the fourth, and the only one that survives a writer who has
-- not read any of them.
--
-- That matters here specifically. The application role holds table-wide INSERT and
-- column-scoped UPDATE on this table, and `status` and `grant_id` are INDEPENDENTLY
-- writable in that list, so the data plane can produce the shape with its granted
-- privileges: an UPDATE setting `grant_id` to NULL on an approved row, or an INSERT naming
-- `status = 'approved'` and omitting the column. Both were demonstrated as `ironauth_app`
-- under RLS, and both are refused now.
--
-- Deliberately NOT `NOT NULL`: a pending, denied or expired request has no grant and must
-- not be forced to invent one. The constraint is conditional on the one status where the
-- column is load bearing.
--
-- VALIDATING, in one statement, and the alternative was tried and reverted.
--
-- The obvious worry is the lock. `/backchannel_authenticate` is a mounted production route
-- and this table is never pruned (0147: "No DELETE: a spent request is invalidated by
-- status, never removed"), so a validating `ADD CONSTRAINT` takes AccessExclusiveLock and
-- scans while holding it, in front of every new reader. The textbook answer is `NOT VALID`
-- plus a separate `VALIDATE CONSTRAINT`, and a previous version of this file did that.
--
-- IT DOES NOTHING HERE, because `MigrationRunner` wraps each file in ONE transaction
-- (`migrate.rs`: `begin`, `raw_sql(migration.sql)`, `commit`). The AccessExclusiveLock taken
-- by the `ADD` is therefore held until COMMIT, across the `VALIDATE` scan, so the split
-- buys exactly nothing: measured on a 12M-row table, a concurrent reader waited the same
-- 0.52s with the split as without it, against 0.13s when the two statements really are in
-- separate transactions. The split cannot be fixed by moving it out of the transaction
-- either, because the `lock_timeout` below is `SET LOCAL` and only reaches these statements
-- BECAUSE they share one.
--
-- So the honest argument is the one 0150 makes for the same shape one file earlier, and it
-- is two parts. No existing row violates the constraint, because nothing in production has
-- ever written an approved row: there is no approval surface yet and the CIBA store methods
-- have no production caller. And the wait is BOUNDED rather than unbounded, by the
-- `lock_timeout` below, so a busy table yields a migration an operator retries instead of a
-- stall queued in front of every reader.
--
-- If this table is ever large and hot at the same time, the fix is a runner that can execute
-- a designated file outside a transaction, not a split that reads as though it helps.

-- Bounded rather than unbounded. TUNABLE for the reasons 0150 sets out at length; the
-- `nullif` is load bearing there and here.
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
    CHECK (status <> 'approved' OR grant_id IS NOT NULL);
