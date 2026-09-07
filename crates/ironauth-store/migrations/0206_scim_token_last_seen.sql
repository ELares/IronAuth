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
-- IT IS ALSO NOT A REVOCATION BYPASS: the RESTRICTIVE one-way policy 0205 installs still applies,
-- and this grant cannot clear `revoked_at` because it does not cover that column.
GRANT UPDATE (last_seen_at) ON scim_connection_tokens TO ironauth_app;
