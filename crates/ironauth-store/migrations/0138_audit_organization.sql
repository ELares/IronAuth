-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The audit row's organization dimension (issue #110).
--
-- Per-organization SIEM streams need to know which organization an event belongs
-- to, and until now nothing recorded it: 0002 carries tenant, environment, actor,
-- target and action, and none of those answers the question. A per-org stream
-- built without this column either ships nothing (filtering on a target prefix
-- that most actions do not have) or ships another organization's events, and the
-- second failure is silent and lands in a third party's SIEM.
--
-- NULLABLE, and that is permanent rather than a migration step. Most audit rows
-- genuinely belong to NO organization: a tenant-level configuration change, a
-- signing-key rotation, an operator action. NULL means "not an organization's
-- event", which is a fact rather than missing data, and a per-org stream matching
-- NULL rows would be the leak this column exists to prevent.
--
-- The value is written by the single audited-write primitive from the acting
-- context, so an event is attributed to an organization only where the caller
-- established one via `ActingContext::in_organization`.
--
-- WHAT THIS MIGRATION DOES NOT YET GIVE YOU, stated plainly: no handler sets it
-- yet, so every row is NULL today and a per-org stream would match nothing. The
-- column and the seam land first because the alternative is threading an
-- organization through the acting context and the storage in one change. The
-- follow-on adds a COVERAGE RATCHET counting how many org-scoped handlers supply
-- it, so the gap becomes a falling number in a test rather than an invisible one,
-- and per-org streams stay unavailable until that count is meaningful. A per-org
-- stream shipped against an all-NULL column would silently under-report, which is
-- the failure this whole column exists to prevent.

ALTER TABLE audit_log ADD COLUMN organization_id text;

-- Per-org export reads (scope, organization, time) in that order. Partial, because
-- the rows that matter to this index are the attributed ones and most rows are not.
CREATE INDEX audit_log_organization_idx
    ON audit_log (tenant_id, environment_id, organization_id, occurred_at)
    WHERE organization_id IS NOT NULL;
