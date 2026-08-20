-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- An approved backchannel request must name the grant its tokens hang off (issue #131).
--
-- Seven rounds of review on the CIBA redemption path found the same family of defect, and
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
-- `status = 'approved'` and omitting the column. Review demonstrated both, as
-- `ironauth_app`, under RLS.
--
-- Deliberately NOT `NOT NULL`: a pending, denied or expired request has no grant and must
-- not be forced to invent one. The constraint is conditional on the one status where the
-- column is load bearing.
--
-- ADDED `NOT VALID`, THEN VALIDATED SEPARATELY, and that split is the whole reason this
-- file is longer than the one statement it contains.
--
-- `/backchannel_authenticate` is a MOUNTED PRODUCTION ROUTE, and 0147 says of this table
-- "No DELETE: a spent request is invalidated by status, never removed", so nothing prunes
-- it and it grows without bound. A validating `ADD CONSTRAINT ... CHECK` takes
-- AccessExclusiveLock and scans every row while holding it, queueing in front of every new
-- reader: every CIBA create and every poll blocks for the length of that scan. `NOT VALID`
-- takes the same lock for a moment and does no scan, and `VALIDATE CONSTRAINT` then scans
-- under ShareUpdateExclusiveLock, which does not block readers or writers at all. This is
-- the same argument 0150 makes one file earlier, and the same `lock_timeout` knob, because
-- an unbounded stall in front of every reader is worse than a migration an operator retries.
--
-- An earlier version of this file argued only that no existing row violates the
-- constraint. That is the VALIDATION question and it is true, and it is not the LOCKING
-- question, which is the one that reaches a live deployment.
--
-- One consequence worth naming for whoever reads this next. While a violating row exists,
-- it is not merely unredeemable, it is UNPOLLABLE: `poll` updates `last_poll_at` on the
-- row, Postgres re-checks the constraint on the new row version, and the client gets an
-- error rather than the uniform answer the poll surface promises. With the constraint
-- validated that state is unreachable, which is exactly why it needs saying here rather
-- than being discovered later.

-- Bounded rather than unbounded: if the table is busy, fail and let the operator retry
-- rather than queue an AccessExclusive request in front of every new reader. TUNABLE for
-- the reasons 0150 sets out at length; the `nullif` is load bearing there and here.
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

-- The scan, under a lock that blocks neither readers nor writers.
ALTER TABLE backchannel_authentication_requests
    VALIDATE CONSTRAINT backchannel_authentication_requests_approved_has_grant;
