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
-- mistake is. The grants are therefore REVOKED and re-issued here, and the revoke has to name
-- the table-wide privilege explicitly: `REVOKE UPDATE ON t` removes the table-wide grant and
-- leaves any column-scoped grant standing, which is exactly the shape wanted.
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
-- `decided_by` is deliberately ABSENT. It records WHO approved, and it is written only by the
-- control-plane decide. A data plane holding UPDATE on it could rewrite the approver of an
-- approval it is otherwise permitted to consume, which is the audit trail for a sensitive
-- action naming somebody who never made the decision. The policy cannot express that: its
-- WITH CHECK constrains state and decided_at and says nothing about decided_by.
REVOKE UPDATE ON agent_vault_approvals FROM ironauth_app;
GRANT UPDATE (state, decided_at, approved_details) ON agent_vault_approvals TO ironauth_app;

-- ---------------------------------------------------------------------------------------
-- native_sso_device_secrets (0182).
--
-- One data-plane write: revoking a device secret, which sets `revoked_at` and nothing else.
-- The table's INSERT grant is untouched -- issuing a device secret IS a data-plane act -- and
-- so is the control plane's read-only grant.
REVOKE UPDATE ON native_sso_device_secrets FROM ironauth_app;
GRANT UPDATE (revoked_at) ON native_sso_device_secrets TO ironauth_app;
