-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0195: when a link's subject was withdrawn downstream (issue #137).
--
-- A link records that a subject IS provisioned. It had no way to record that the subject has
-- since been withdrawn, and 0190 deliberately does not delete the row when that happens:
--
--     a deprovision leaves the link so a rehire resolves through it, exactly as 0184 argues for
--     the inbound direction
--
-- That is the right call and this column is what makes it work. Without it the link says
-- "provisioned" for ever, and two things follow, both of which the review found:
--
--   1. THE WORKER RE-WITHDRAWS ON EVERY LATER EVENT. `scope_decision` reads the link's PRESENCE
--      as "this connection provisioned them", so a subject who left scope is out of scope with a
--      link on every subsequent pass, and every pass sends another deprovision. Against a
--      downstream that answers 404 to a repeat delete that is merely wasteful; against one that
--      answers 4xx it is a permanent refusal recorded against a person who is already gone.
--
--   2. THE HEALTH SURFACE CALLS THEM HEALTHY. Criterion 2's per-resource listing reports
--      `last_synced_at` and no error for a subject who has been removed, so an operator reading
--      it sees a successfully provisioned person who is not there.
--
-- NULLABLE, and NULL means currently provisioned. A boolean would answer "was this person
-- withdrawn" and not "when", and the when is what an operator asks first when a rehire's access
-- is missing.
--
-- Expand phase: a new nullable column with no default. Every existing row reads as provisioned,
-- which is what it was, and an old binary neither selects nor writes it.

ALTER TABLE scim_push_links ADD COLUMN deprovisioned_at timestamptz;

-- THE GRANT GOES WITH THE COLUMN, not in a later migration. 0189 deferred the worker's grants
-- and the deferral cost a whole correction (0192) because the code that needed them shipped
-- first; the lesson recorded there applies here, and the worker that writes this column is in
-- the same change.
GRANT UPDATE (deprovisioned_at) ON scim_push_links TO ironauth_app;

-- The operator-facing question this answers is "who has this connection removed, and when",
-- which is a listing filtered on the column, so it is worth an index rather than a scan of every
-- link the connection has ever written.
CREATE INDEX scim_push_links_deprovisioned
    ON scim_push_links (tenant_id, environment_id, connection_id, deprovisioned_at)
    WHERE deprovisioned_at IS NOT NULL;

COMMENT ON COLUMN scim_push_links.deprovisioned_at IS
    'Issue #137: when this subject was withdrawn downstream. NULL means currently provisioned. '
    'The row survives a withdrawal so a rehire resolves through it (0190), which is why the '
    'state needs a column rather than the row''s absence.';
