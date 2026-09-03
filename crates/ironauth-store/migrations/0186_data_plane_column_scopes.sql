-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Narrow three TABLE-WIDE data-plane UPDATE grants to the columns their writers name.
--
-- `migration.rs::the_data_plane_holds_no_table_wide_update_on_any_table` is the whole-surface
-- guard on the issue #31 lesson: the data plane must never hold an UPDATE it can point at any
-- column, because one is a rewrite of whatever the schema comes to hold later, not of what the
-- code writes today. Three tables shipped holding one anyway and the guard was RED on main:
-- `agent_vault_connections` (0178), `agent_vault_approvals` (0181) and
-- `native_sso_device_secrets` (0182). This is the repair.
--
-- WHY A NEW MIGRATION RATHER THAN AN EDIT. 0178, 0181 and 0182 are shipped and their whole
-- file content is checksummed, so editing one is not available even though it is where the
-- mistake is. The grants are therefore REVOKED and re-issued here.
--
-- READ THIS BEFORE COPYING THIS FILE FOR A FOURTH TABLE. `REVOKE UPDATE ON t FROM role` clears
-- BOTH FORMS: the table-wide grant AND every column-scoped grant on that table. It is not a
-- narrowing operator. Measured:
--
--   GRANT  UPDATE (a) ON probe TO r;   -- column t, table f
--   GRANT  UPDATE     ON probe TO r;   -- column t, table t
--   REVOKE UPDATE     ON probe FROM r; -- column f, table f   <-- the column grant is gone too
--
-- So the GRANT that follows a REVOKE must re-issue the WHOLE intended set, not just the part
-- being added.
--
-- TWO QUALIFICATIONS, both measured, because a rule aimed at a future author has to be usable
-- rather than merely true:
--
--   * `REVOKE UPDATE ON t FROM r` does NOT clear what `r` holds through PUBLIC or through role
--     membership -- `has_column_privilege` still answers true. Inert here (the ironauth roles
--     have no memberships and no PUBLIC grant reaches an app table), but a narrowing that has
--     to be complete cannot rely on this statement alone.
--   * The converse trap: `REVOKE UPDATE (a) ON t FROM r` against a TABLE-WIDE grant removes
--     NOTHING. An author narrowing by revoking the columns they want gone silently achieves
--     nothing at all, which is the same failure this header exists to prevent approached from
--     the other side. Revoke the privilege, then re-grant the columns. It is safe on these three tables only because none of them carried a prior
-- column-scoped UPDATE grant for `ironauth_app` -- checked across all 186 migrations. That is
-- NOT true of every table: `scim_membership_activation` holds
-- `GRANT UPDATE (active, updated_at) ... TO ironauth_app` from 0185, and a later migration
-- written to a "revoke leaves column grants standing" reading would silently delete both and
-- break the SCIM activation writer at runtime with SQLSTATE 42501 -- the exact failure this
-- header exists to prevent. An earlier version of this paragraph said precisely that, backwards.
--
-- HOW THE COLUMN LISTS WERE DERIVED. Not from what each surface conceptually does, but from
-- the SET list of every statement the data plane actually executes against the table. Postgres
-- checks the column privilege for every column a SET list NAMES, whether or not the value
-- changes, so a list shorter than the statement fails with SQLSTATE 42501 at runtime rather
-- than at deploy -- the failure mode 0185's own header records having hit.
--
-- EXPAND-SAFE, and this is the one that needs the argument, because it REMOVES a privilege.
-- An old binary running beside a migrated database keeps every write it performs: the columns
-- granted below are the union of the SET lists in the code that shipped with 0178 through
-- 0185, so no statement that ran before this migration is refused after it. What is removed is
-- the ability to write columns no statement names.

-- ---------------------------------------------------------------------------------------
-- agent_vault_connections (0178, widened by 0181).
--
-- Two data-plane writers: `refresh_stored_credential`, which replaces the sealed credential
-- after a refresh, and the failure path that marks a connection broken rather than deleting
-- it. Between them they name the eight columns below. Nothing here grants the data plane a
-- write on the row's IDENTITY (`id`, `agent_id`, `provider`, the scope columns) or on the
-- refresh CONFIGURATION (`refresh_token_endpoint`, `refresh_client_id`,
-- `refresh_client_secret_sealed`, `refresh_client_secret_dek_version`) -- that configuration
-- names the downstream OAuth client and its secret, and a data plane that could repoint it
-- could redirect a refresh to a server it chose.
REVOKE UPDATE ON agent_vault_connections FROM ironauth_app;
GRANT UPDATE (
    access_token_sealed,
    access_token_dek_version,
    refresh_token_sealed,
    refresh_token_dek_version,
    expires_at,
    state,
    last_error,
    updated_at
) ON agent_vault_connections TO ironauth_app;

-- ---------------------------------------------------------------------------------------
-- agent_vault_approvals (0181).
--
-- The data plane RETIRES an approval: it consumes an approved one and expires a lapsed one.
-- 0181's RESTRICTIVE policy already bounds which rows it may touch and which states it may
-- write; what it did not bound is which COLUMNS, and the two answers are independent.
--
-- The union of the two data-plane statements and nothing else:
--
--   `retire_timed_out` (repository.rs)   SET state, decided_at
--   `consume`          (repository.rs)   SET state
--
-- `decide_with_event` is the third statement against this table and it is CONTROL plane only --
-- its one caller is `ironauth-admin`'s agent surface, through `management()`. Its SET list
-- names `state, approved_details, decided_by, decided_at`, and an earlier draft of this grant
-- took that list and hand-dropped `decided_by`, which is self-contradictory: if `decide` ran
-- here, dropping a column it names would break it, and since it does not, `approved_details`
-- had no business in the list either. A reviewer measured that removing it leaves every store
-- suite green.
--
-- TWO COLUMNS ARE THEREFORE ABSENT, and both matter.
--
-- `decided_by` records WHO approved. A data plane holding UPDATE on it could rewrite the
-- approver of an approval it is otherwise permitted to consume, so the audit trail for a
-- sensitive action would name somebody who never made the decision.
--
-- `approved_details` records WHAT the approver agreed to, which may be narrower than what was
-- requested. 0181's RESTRICTIVE policy does not protect it: its WITH CHECK reads
-- `(approved_details IS NULL OR state = 'consumed')` and never compares against the OLD row, so
-- on the approved -> consumed transition any value passes. 0181's own prose one screen above
-- says the check keeps "the decision and the approved set unchanged"; the predicate does not
-- say that, and the column grant is what actually holds it.
REVOKE UPDATE ON agent_vault_approvals FROM ironauth_app;
GRANT UPDATE (state, decided_at) ON agent_vault_approvals TO ironauth_app;

-- ---------------------------------------------------------------------------------------
-- native_sso_device_secrets (0182).
--
-- One data-plane write: revoking a device secret, which sets `revoked_at` and nothing else.
-- The table's INSERT grant is untouched -- issuing a device secret IS a data-plane act -- and
-- so is the control plane's read-only grant.
REVOKE UPDATE ON native_sso_device_secrets FROM ironauth_app;
GRANT UPDATE (revoked_at) ON native_sso_device_secrets TO ironauth_app;
