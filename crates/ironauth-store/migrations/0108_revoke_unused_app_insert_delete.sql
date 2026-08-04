-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Retire six data-plane privileges that no caller uses (the #31 lesson applied to INSERT
-- and DELETE, after 0018, 0106 and 0107 finished it for UPDATE).
--
-- #31 objects to a standing capability with no caller, not merely to a grant that is too
-- wide in its columns. 0106 already applied that reading once, when `signing_keys` took no
-- update grant at all because nothing in the workspace updates it. This migration asks the
-- same question of the two verbs the UPDATE sweep did not cover.
--
-- METHOD, and it is the same one 0107 used because a statement-derived list is role blind.
-- Every `INSERT INTO <table>` and `DELETE FROM <table>` in the workspace was enumerated
-- against the tables where ironauth_app holds the matching privilege, and each site's
-- enclosing repository was resolved to the store that exposes it. The six below have NO
-- site at all: not a data-plane one, not a control-plane one, none. Nothing is re-granted,
-- because there is no caller to re-grant for.
--
-- Two of them are RETIRED QUEUES, and they lose every privilege rather than one.
--
-- `session_ended_events` and `backchannel_logout_deliveries` were each a dedicated queue
-- until issue #104 moved delivery onto the generic outbox. Both are now unreferenced by
-- any statement in the workspace: `SessionEventOutboxRepo` is a typed facade whose rows
-- live in `outbox_messages` under a consumer discriminator, and back-channel delivery is a
-- consumer on that same substrate. The tables still exist and still hold their rows, so
-- this migration is about the ROLE and not about the data: whether the tables should
-- outlive their contents is a retention question and is deliberately not answered here.
--
-- Their scoped UPDATE grants are revoked in the column form as well as the table form. A
-- table-level REVOKE does not remove a privilege that was granted per column, so revoking
-- only `UPDATE ON <table>` would leave the columns 0024 and 0025 named still writable.
--
-- The other four are LIVE tables that have never had a delete path. `sms_config`,
-- `sms_route_stats`, `trusted_devices` and `webauthn_challenges` are all written and read
-- on the data plane, but removal on each is either a soft delete carried by an update
-- column or simple expiry that nothing reaps. Should a reaper ever be written, the grant
-- it needs is one line and it will then be attributable to that caller, which is the whole
-- of the difference between this state and the previous one.
--
-- Every statement is a REVOKE. No table is created or altered, so there is no
-- row-level-security obligation and no `scripts/query-audit.sh` entry: an EXPAND phase
-- with no contract half.

-- 1. The two retired queues (#104). No privilege of any kind survives for the data plane.

REVOKE UPDATE (claimed_at, delivered_at) ON session_ended_events FROM ironauth_app;
REVOKE SELECT, INSERT, UPDATE ON session_ended_events FROM ironauth_app;

REVOKE UPDATE (attempts, next_attempt_at, claimed_at, last_error, delivered_at,
               dead_lettered_at)
    ON backchannel_logout_deliveries FROM ironauth_app;
REVOKE SELECT, INSERT, UPDATE ON backchannel_logout_deliveries FROM ironauth_app;

-- 2. Live tables whose DELETE grant has never had a caller. Only DELETE is touched; every
--    other privilege on these four stays exactly as it was.

REVOKE DELETE ON sms_config FROM ironauth_app;
REVOKE DELETE ON sms_route_stats FROM ironauth_app;
REVOKE DELETE ON trusted_devices FROM ironauth_app;
REVOKE DELETE ON webauthn_challenges FROM ironauth_app;
