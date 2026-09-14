-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Narrow the data plane's UPDATE on the hot-state tables to the columns that are
-- actually written (issue #147, correcting 0226 and 0227).
--
-- 0226 and 0227 granted `ironauth_app` a TABLE-WIDE UPDATE:
--
--     GRANT SELECT, INSERT, UPDATE, DELETE ON hot_state TO ironauth_app;
--     GRANT SELECT, INSERT, UPDATE ON hot_state_invalidation_cursors TO ironauth_app;
--
-- which this repository forbids (the #31 lesson, enforced by
-- `the_data_plane_holds_no_table_wide_update_on_any_table`). A table-wide UPDATE lets a
-- compromised or buggy data-plane path rewrite the SCOPE COLUMNS of a row it legitimately
-- reached -- moving an entry into another tenant, or repointing a cursor at another
-- environment -- and neither is an operation any caller performs. Row-level security
-- decides WHICH ROWS a statement may touch; it does not constrain which COLUMNS of those
-- rows may be rewritten, so the grant is the only thing standing there.
--
-- The columns kept are exactly the ones the repository writes:
--
--   hot_state                        value, expires_at
--       (`DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`, in the
--        put, the guarded claim, and the tiered populate)
--   hot_state_invalidation_cursors   applied_through, updated_at
--       (`DO UPDATE SET applied_through = GREATEST(...), updated_at = EXCLUDED.updated_at`)
--
-- INSERT is untouched, so a first write still supplies every column; only the rewrite of
-- an existing row is narrowed. DELETE on hot_state is also untouched: it has real callers
-- (the delete, the per-use prune, and the expiry sweep), and a DELETE grant cannot move a
-- row between scopes.
--
-- # Safe mid-upgrade, which is why this is an expand-phase migration
--
-- The PREVIOUS binary performs exactly the same two updates as the new one, so the
-- narrowed grant permits everything it does. A REVOKE that removed a privilege a running
-- binary still used would be a contract-phase change; this one removes only privileges
-- that no binary, old or new, has ever exercised.

REVOKE UPDATE ON hot_state FROM ironauth_app;
GRANT UPDATE (value, expires_at) ON hot_state TO ironauth_app;

REVOKE UPDATE ON hot_state_invalidation_cursors FROM ironauth_app;
GRANT UPDATE (applied_through, updated_at) ON hot_state_invalidation_cursors TO ironauth_app;
