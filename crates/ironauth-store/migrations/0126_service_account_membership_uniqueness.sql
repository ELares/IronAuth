-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- One live membership per service account per organization (issue #99).
--
-- 0084 stated this invariant for users with a partial unique index over
-- (tenant, environment, organization_id, user_id) restricted to live rows. 0124 relaxed
-- user_id to nullable so a membership could bind a service account instead, and a NULL is
-- distinct from every other NULL in a unique index, so that index stopped saying anything
-- about the new shape: two live memberships for the SAME service account in the SAME
-- organization satisfy it. This is the counterpart it needs.
--
-- The predicate matches 0084's reasoning exactly. A soft-deleted membership does not occupy
-- the key, so re-adding a removed principal REVIVES the dead row rather than tripping a
-- permanent conflict, and every read (which filters deleted_at IS NULL) agrees with this
-- invariant on precisely the live set. The service_account_id IS NOT NULL clause keeps user
-- memberships, whose service_account_id is NULL, out of an index that has nothing to say
-- about them.
CREATE UNIQUE INDEX org_memberships_org_service_account_live_uniq
    ON org_memberships (tenant_id, environment_id, organization_id, service_account_id)
    WHERE deleted_at IS NULL AND service_account_id IS NOT NULL;
