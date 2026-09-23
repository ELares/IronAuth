-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The rotation state machine's lifecycle grant (issue #160).
--
-- Migration 0106 revoked the table-wide UPDATE on signing_keys from the app role
-- (the #31 lesson). The automated rotation stamps exactly two columns at a handoff
-- (retire_at, expire_at) and nothing else, so the grant comes back COLUMN-SCOPED:
-- a compromised drain can never rewrite key material or publication instants, and
-- the manual rotation path (which previously relied on the table-wide grant) keeps
-- working through the same two columns.
--
-- EXPAND: additive grant only; nothing existing changes.
GRANT UPDATE (retire_at, expire_at) ON signing_keys TO ironauth_app;
GRANT UPDATE (retire_at, expire_at) ON signing_keys TO ironauth_control;
-- The management plane (the admin surface's store) lists the keys for the rotation
-- state view (issue #160); 0005 granted the app role only.
GRANT SELECT ON signing_keys TO ironauth_control;