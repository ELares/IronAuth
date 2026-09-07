-- When each SCIM token was last used to provision (issue #140).
--
-- WHAT AN IT ADMIN CANNOT OTHERWISE FIND OUT. #140 asks for "per-connection health/sync status
-- (last request seen, recent errors)" and for a connection check "verifying the token and
-- reporting recent sync activity". Until now the portal could say what a connection's credentials
-- ARE and when they stop, and nothing about whether anything has ever used them. Those are
-- different questions, and the gap between them is where a failed setup lives: an admin who
-- pastes a token into the wrong field, or into the right field of the wrong application, sees a
-- connection that looks configured and provisions nothing.
--
-- PER TOKEN, NOT PER CONNECTION, because the question that matters during a rotation is which
-- token is actually in use. A rotation gives the customer a new token and an overlap to paste it
-- in; a connection-level timestamp keeps moving throughout that window on the strength of the OLD
-- token and says nothing about whether the cutover happened. Per token, the portal can say the
-- new credential has not been used yet -- which is the one thing that predicts the outage at the
-- end of the overlap.
--
-- NULL MEANS NEVER USED, which is a distinct and useful state: a token minted an hour ago that
-- has never authenticated is a setup in progress, and one minted a month ago that never has is a
-- setup that failed and nobody noticed.
ALTER TABLE scim_connection_tokens
    ADD COLUMN last_seen_at timestamptz;

-- SINCE WHEN THIS ROW HAS BEEN OBSERVED AT ALL, which is what makes a NULL `last_seen_at`
-- readable.
--
-- WITHOUT IT, NULL MEANS TWO OPPOSITE THINGS. Every token row that exists when this migration
-- runs -- the whole installed base, including every row 0205 backfilled -- gets a NULL
-- `last_seen_at`, and it means "nobody was watching", not "nothing has used it". A surface that
-- rendered NULL as "never used" would tell every customer of every upgraded deployment that
-- their working connection has never been called, on the day of the upgrade. A row created
-- AFTER this point has been watched for its whole life, and there NULL genuinely does mean
-- never used -- which is the diagnosis this feature exists to deliver, a token pasted into the
-- wrong field.
--
-- THE DEFAULT DOES THE BACKFILL. Adding a NOT NULL column with a default stamps every existing
-- row with the migration's own `now()`, which is later than those rows' `created_at`; a row
-- inserted afterwards takes `now()` at insert, equal to its own `created_at`. So the test is
-- simply whether `observed_since <= created_at`, and it needs no separate backfill statement and
-- no reference to the migration ledger.
ALTER TABLE scim_connection_tokens
    ADD COLUMN observed_since timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN scim_connection_tokens.observed_since IS
    'When this row began being observed for use. Equal to created_at for rows inserted after '
    'migration 0206, and later than it for rows that already existed -- so a NULL last_seen_at '
    'means "never used" only when observed_since <= created_at (issue #140).';

COMMENT ON COLUMN scim_connection_tokens.last_seen_at IS
    'When this token last authenticated a SCIM request, or NULL if it never has. Written by the '
    'data plane on the authentication path, throttled so an ordinary provisioning run does not '
    'write once per request (issue #140).';

-- THE DATA PLANE WRITES IT, which is a departure from every other column here and needs saying.
-- Provisioning requests authenticate against the data-plane role, so it is the only role in a
-- position to observe a token being used at all; the control plane never sees one.
--
-- COLUMN-SCOPED, exactly as `portal_links.consumed_at` is for the same role (migration 0203). A
-- table-wide UPDATE would let the data-plane role rewrite `expires_at` and `revoked_at` -- the
-- two columns that decide whether a credential still works -- and recording a timestamp needs
-- neither. `migration.rs::the_data_plane_holds_no_table_wide_update_on_any_table` reads
-- `information_schema.table_privileges` and fails on the table-wide form.
--
-- IT IS NOT A REVOCATION BYPASS, and the reason is the GRANT rather than the policy. 0205's
-- RESTRICTIVE one-way policy is `TO ironauth_control`, so it does not constrain this role at all
-- -- and if it did it would REFUSE this write, since its `WITH CHECK (revoked_at IS NOT NULL OR
-- expires_at IS NOT NULL)` fails for an ordinary live token with neither set. What stops the data
-- plane clearing `revoked_at` is that this grant does not name that column, and column-scoped
-- UPDATE privileges are enforced per column by Postgres itself.
--
-- 0205 SAYS OF THIS ROLE "It may not write", under a heading arguing that a provisioning
-- credential able to mint another would be an escalation. That argument still holds and this
-- grant does not weaken it -- a timestamp mints nothing -- but the sentence is now literally
-- false, and it is stated in a shipped migration this project checksums whole, so it cannot be
-- edited in place. This paragraph is its retraction: as of 0206 the data plane writes exactly
-- one column of this table, `last_seen_at`, and nothing else.
GRANT UPDATE (last_seen_at) ON scim_connection_tokens TO ironauth_app;
