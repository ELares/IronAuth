-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Column-scope the last seven table-wide data-plane UPDATE grants (issue #218, finishing
-- what 0018 started for `clients` and 0106 continued for the consume latches).
--
-- After this no table grants ironauth_app a table-wide UPDATE. The #31 lesson is that such
-- a grant lets the data-plane role rewrite ANY column, including the immutable ones that
-- carry the lineage the rest of the system trusts (ids, scope keys, digests, successor
-- pointers).
--
-- EVERY column list below was derived the same way and the method is the point, because
-- the obvious shortcut is wrong. Each UPDATE statement the store issues against the table
-- was read, and each one's enclosing repository was then resolved to the store that
-- exposes it: an `ActingStore` or `ScopedStore` accessor is the DATA plane, an
-- `ActingManagementStore` one is the control plane. A list derived from statements alone,
-- without that attribution, would silently hand the data-plane role columns that belong to
-- the management plane.
--
-- `organizations` IS THAT CASE, and it is why this migration revokes without re-granting.
-- All three of its UPDATE sites (`create`, `delete`, `set_state`) live on
-- `ActingOrganizationRepo`, which is exposed by `ActingManagementStore` alone. Migrations
-- 0027 and 0084 already grant `deleted_at` and `state` to ironauth_control for exactly
-- those paths, and 0084 grants ironauth_app only SELECT. The data plane never updates an
-- organization, so it gets no UPDATE at all. Narrowing this table to the columns its
-- statements name would have WIDENED the app role's rights, which is worse than the
-- table-wide grant being replaced.
--
-- Only UPDATE is touched. `organizations` also carries table-wide INSERT and DELETE to
-- ironauth_app from 0001; narrowing those needs its own attribution pass and its own
-- migration, and is deliberately not smuggled in here.
--
-- Migration safety obligation (see migrate.rs): every statement is a REVOKE or a GRANT.
-- No table is created or altered, so there is no row-level-security obligation and no new
-- entry for scripts/query-audit.sh, and this is an EXPAND with no contract phase. Each
-- REVOKE precedes its re-GRANT so the narrowing cannot be defeated by ordering.

-- The data plane never updates an organization: control-plane only, no re-grant.
REVOKE UPDATE ON organizations FROM ironauth_app;

-- One shared statement, reached from issue, classify_miss, revoke and the session and
-- family cascades: all of them only stamp the revocation instant.
REVOKE UPDATE ON grants FROM ironauth_app;
GRANT UPDATE (revoked_at) ON grants TO ironauth_app;

-- Revocation, reuse detection, and the rotation reconciliation that re-points a family at
-- the session it now belongs to.
REVOKE UPDATE ON refresh_families FROM ironauth_app;
GRANT UPDATE (revoked_at, reuse_detected_at, session_ref)
    ON refresh_families TO ironauth_app;

-- Rotation stamps the instant and the successor it rotated into. The token digest and its
-- lineage are immutable.
REVOKE UPDATE ON refresh_tokens FROM ironauth_app;
GRANT UPDATE (rotated_at, successor_jti) ON refresh_tokens TO ironauth_app;

-- The fixed-window counter and the window it belongs to.
REVOKE UPDATE ON dcr_rate_counters FROM ironauth_app;
GRANT UPDATE (count, window_start) ON dcr_rate_counters TO ironauth_app;

-- The upsert's ON CONFLICT branch. `ON CONFLICT ... DO UPDATE SET` needs UPDATE privilege
-- on exactly the columns it names, which a grep for `UPDATE <table> SET` alone would miss.
REVOKE UPDATE ON scope_step_up_policies FROM ironauth_app;
GRANT UPDATE (min_acr, max_auth_age_secs, updated_at)
    ON scope_step_up_policies TO ironauth_app;

-- Advancing a flow rewrites its state document and rotates the submit token; consuming it
-- stamps the instant. The flow id, its scope and its journey are immutable.
REVOKE UPDATE ON flows FROM ironauth_app;
GRANT UPDATE (state, submit_token, consumed_at) ON flows TO ironauth_app;
