-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Column-scope the data-plane UPDATE on the single-use consume latches, and take the
-- unused one away entirely (issue #218, finishing the #31 lesson for this group).
--
-- The #31 lesson is that ironauth_app never holds a TABLE-WIDE UPDATE: a table-wide grant
-- lets the data-plane role rewrite any column, including ones that must be immutable
-- (ids, scope keys, created-at, digests, lineage). Migration 0018 applied it to `clients`
-- by REVOKE then a column-scoped re-GRANT, and this does the same for five more tables.
--
-- WHY THESE FIVE TOGETHER
--
-- Four of them are the same shape: a single-use latch the data plane CONSUMES exactly
-- once, whose only data-plane mutation is stamping the consumption instant. Nothing else
-- about the row may ever change, and that is precisely what a table-wide grant failed to
-- say. The fifth is `signing_keys`, which the data plane never updates at all.
--
-- The column lists are derived from the code rather than from the schema: every UPDATE
-- statement the store issues against each table was read, and each one's enclosing
-- repository was checked to confirm it is a SCOPED (data-plane) repo rather than a
-- management one. That distinction is the trap here. `organizations` also carries a
-- table-wide app grant, and its `deleted_at` and `state` updates look like data-plane
-- writes until you notice migrations 0027 and 0084 already grant exactly those two columns
-- to ironauth_control, and 0084 gives ironauth_app only SELECT. Narrowing that one to the
-- columns its UPDATE statements name would have GRANTED the app role two columns it must
-- not hold. It is deliberately left for its own change, with the other six, rather than
-- swept in on an attribution this migration cannot make safely.
--
-- signing_keys takes NO update grant. Nothing in the workspace issues `UPDATE
-- signing_keys` at all: rotation inserts a new key and retirement is expressed by the
-- lifecycle columns written at insert. A grant nothing exercises is a standing capability
-- with no caller, which is the same thing #31 objected to.
--
-- Migration safety obligation (see migrate.rs): every statement is a REVOKE or a GRANT.
-- No table is created or altered, so there is no row-level-security obligation and no new
-- entry for scripts/query-audit.sh, and this is an EXPAND with no contract phase. The
-- REVOKE precedes each re-GRANT so the narrowing cannot be defeated by ordering.

REVOKE UPDATE ON authorization_codes FROM ironauth_app;
GRANT UPDATE (consumed_at) ON authorization_codes TO ironauth_app;

REVOKE UPDATE ON pushed_authorization_requests FROM ironauth_app;
GRANT UPDATE (consumed_at) ON pushed_authorization_requests TO ironauth_app;

REVOKE UPDATE ON fedcm_assertion_nonces FROM ironauth_app;
GRANT UPDATE (consumed_at) ON fedcm_assertion_nonces TO ironauth_app;

REVOKE UPDATE ON federation_login_states FROM ironauth_app;
GRANT UPDATE (consumed_at) ON federation_login_states TO ironauth_app;

REVOKE UPDATE ON signing_keys FROM ironauth_app;
