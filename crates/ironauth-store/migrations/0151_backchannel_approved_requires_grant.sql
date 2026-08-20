-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- An approved backchannel request must name the grant its tokens hang off (issue #131).
--
-- Six rounds of review on the CIBA redemption path found the same family of defect, and
-- every one of them was reachable only through an approved row whose `grant_id` is NULL.
-- The tokens have nothing to hang off, a revocation has nothing to reach, and nothing in
-- the database links the issued tokens back to the `auth_req_id`.
--
-- The code now refuses that shape at three places: `decide` will not create it,
-- `approved_details` will not report it as redeemable, and `redeem`/`redeem_approved` will
-- not consume it. This is the fourth, and it is the only one that survives a writer who has
-- not read any of them.
--
-- That matters here specifically. The application role holds table-wide INSERT and
-- column-scoped UPDATE on this table, and `status` and `grant_id` are INDEPENDENTLY
-- writable in that list, so the data plane can produce the shape with its granted
-- privileges: an UPDATE setting `grant_id` to NULL on an approved row, or an INSERT naming
-- `status = 'approved'` and omitting the column. Review demonstrated both, as
-- `ironauth_app`, under RLS. A rule that must survive a future writer belongs in a CHECK,
-- which is the same argument this table's own push-mode vocabulary constraint makes.
--
-- Deliberately NOT NOT NULL: a pending, denied or expired request has no grant and must
-- not be forced to invent one. The constraint is conditional on the one status where the
-- column is load bearing.
--
-- Safe to apply: nothing in production has ever written an approved row, because there is
-- no approval surface yet. The CIBA methods have no production caller.

ALTER TABLE backchannel_authentication_requests
    ADD CONSTRAINT backchannel_authentication_requests_approved_has_grant
    CHECK (status <> 'approved' OR grant_id IS NOT NULL);
