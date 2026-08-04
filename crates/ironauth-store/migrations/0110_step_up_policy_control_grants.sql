-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Control-plane grants for the per-scope step-up policy table, so the management HTTP
-- surface issue #262 adds can reach it at all.
--
-- THE PLANE DIFFERENCE IS THE WHOLE REASON THIS MIGRATION EXISTS, and it is the thing
-- "the store repos and the CLI already exist, this is just the HTTP surface over them"
-- hides. The CLI resolves a DATA-PLANE DSN and writes as `ironauth_app`, which 0047
-- granted. The management API runs as `ironauth_control`, which 0047 granted nothing.
-- Mounting the routes without this produces a 500 on every write and an empty list on
-- every read, which is exactly the dead-surface shape issue #441 described and
-- 0098 fixed for the ban surface.
--
-- No new row-level-security policy is needed. 0047's `scope_step_up_policies_tenant_isolation`
-- is role agnostic: it compares against `ironauth.tenant_id` and `ironauth.environment_id`,
-- which the scoped transaction sets whichever role opened it.
--
-- SELECT, INSERT and DELETE are table scoped, for the reason 0098 records: the granted
-- statements touch every column between them, so a column list naming all of them would
-- restrict nothing while silently breaking on the next column added.
--
-- UPDATE is COLUMN SCOPED, matching what 0107 left the data plane. The management upsert
-- is `INSERT ... ON CONFLICT DO UPDATE`, and that branch needs UPDATE on exactly the
-- columns it names. `id`, `scope`, `tenant_id`, `environment_id` and `created_at` are the
-- policy's identity and are never rewritten by a set: an UPDATE grant covering them would
-- let a management path silently retarget an existing policy at a different scope token,
-- which is the edit an audit trail recording only "policy set" could not distinguish from
-- an ordinary update.

GRANT SELECT, INSERT, DELETE ON scope_step_up_policies TO ironauth_control;
GRANT UPDATE (min_acr, max_auth_age_secs, updated_at)
    ON scope_step_up_policies TO ironauth_control;
