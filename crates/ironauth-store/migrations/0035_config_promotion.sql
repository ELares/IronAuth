-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Server-side config promotion apply privileges (issue #44).
--
-- The promotion engine's DIFF and PLAN are pure logic; the APPLY transactionally
-- mutates the promotable resource tables and writes its audit row in ONE
-- transaction, so it runs as a single role on a single connection. Promotion is a
-- CONTROL-plane management operation, so the control role is granted exactly the
-- privileges the apply needs on the promoted resource types: create, overwrite,
-- and remove a resource server, a DCR policy, or an environment variable, and read
-- the PRESENCE of an environment secret to validate a reference.
--
-- Least privilege (the #31 lesson) is preserved. Every UPDATE is COLUMN-SCOPED to
-- exactly the columns an apply rewrites (never a table-wide UPDATE). The control
-- role is granted only SELECT on environment_secrets, and it holds no envelope
-- master key, so a secret's ciphertext stays opaque to it and a secret VALUE is
-- never reachable through the control plane (the 0034 write-only discipline is
-- intact: promotion validates that a named secret EXISTS, never reads its value).
-- The data-plane app role's privileges are unchanged.
--
-- This migration adds no schema object, only grants, so it is an additive expand.

-- Resource servers: create, column-scoped overwrite, and remove. The control role
-- already reads them for the snapshot export (issue #43); apply completes the set.
GRANT INSERT, DELETE ON resource_servers TO ironauth_control;
GRANT UPDATE (token_format, access_token_ttl_secs) ON resource_servers TO ironauth_control;

-- DCR policies: the control role already has SELECT and INSERT (issue #31); add
-- the column-scoped overwrite of the primitive list and the remove.
GRANT UPDATE (primitives) ON dcr_policies TO ironauth_control;
GRANT DELETE ON dcr_policies TO ironauth_control;

-- Environment variables: the control role already has SELECT for the snapshot
-- export (issue #45); add create, the column-scoped overwrite, and remove.
GRANT INSERT, DELETE ON environment_variables TO ironauth_control;
GRANT UPDATE (value, version, updated_at) ON environment_variables TO ironauth_control;

-- Environment secrets: SELECT only, for the plan-time and apply-time PRESENCE
-- check of a secret reference. The control role holds no master key, so this
-- reveals only that a named secret exists (and its opaque ciphertext), never a
-- secret value.
GRANT SELECT ON environment_secrets TO ironauth_control;
