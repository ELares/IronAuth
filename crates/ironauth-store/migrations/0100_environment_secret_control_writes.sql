-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Control-plane writes on environment_secrets (issue #250).
--
-- Issue #250 moves the OUTBOUND lazy-migration credential-verification enablement
-- AND its shared bearer token off the deployment-global `[admin]` config and into
-- the per-environment secrets surface (issue #45), so each environment carries its
-- own independent, sealed, rotatable credential instead of one global value with a
-- single authorized scope. The management API is the plane an operator drives that
-- from, and the management API authenticates as `ironauth_control`.
--
-- Migration 0034 granted `ironauth_control` NOTHING on environment_secrets, and
-- 0035 added SELECT for the promotion plan's reference-presence check. So the read
-- half of issue #250 already works; the WRITE half (enable, rotate, disable) does
-- not. This migration grants exactly the privileges those three operations need,
-- and nothing else.
--
-- # Correcting the record 0035 left
--
-- The 0035 header says the control role "holds no envelope master key so a secret
-- VALUE stays unreachable through the control plane". That stopped being true at
-- 0037: issue #52 gave the control plane end-to-end user management, which is a PII
-- surface, so 0037 granted `ironauth_control` SELECT and INSERT on `tenant_keks`
-- and `tenant_deks`, and the boot path attaches the platform master key to the
-- control-plane store (`crates/ironauth/src/main.rs`, the management-plane store
-- construction). A secret value has therefore been openable through the control
-- plane since 0037. This migration does not change that reachability by one row; it
-- only makes the WRITE side possible too, and states the true position so the next
-- reader is not misled by 0035's stale sentence.
--
-- What still holds, and is the property that matters: the config-promotion SNAPSHOT
-- EXPORT never reads a secret value. That is a property of the export code path
-- (it reads `environment_variables`, never `environment_secrets`), pinned by
-- `config_snapshot` tests, not a property of the grant table.
--
-- # Least privilege, and why the GRANT alone was not it
--
-- INSERT and DELETE for the first write and the disable, plus a COLUMN-SCOPED
-- UPDATE over exactly the four columns an overwrite (a rotation) rewrites: the
-- sealed value, its DEK version, the write version, and the update instant. Never a
-- table-wide UPDATE (the #31 lesson), and never a grant on `name`, `id`,
-- `tenant_id`, `environment_id`, or `created_at`. These are the same four columns
-- 0034 granted the data-plane role.
--
-- Those column grants are exactly as narrow as they look, and MEASURED to be: as
-- `ironauth_control` inside a scope-bound transaction, an UPDATE of `name` or of
-- `environment_id` is `permission denied`, a cross-scope UPDATE and DELETE affect
-- zero rows, and a cross-scope INSERT violates the isolation policy's WITH CHECK.
--
-- What the grants do NOT do, and what an earlier draft of this header wrongly
-- claimed they did: they do not stop the control plane creating a secret under ANY
-- name in its bound scope. `GRANT INSERT` is table wide (INSERT has a column form,
-- but withholding `name` from it would only mean the column defaults, and it is NOT
-- NULL with no default, so the write would simply fail); `GRANT DELETE` has no
-- column form at all. INSERT plus DELETE is therefore a RENAME, and a REPLACE of any
-- other secret in the scope, one statement pair at a time. "Can rotate a value in
-- place but can neither rename one nor move one between scopes" was true of UPDATE
-- and false of the pair.
--
-- So the real fence is the one Postgres offers for exactly this, and it is below: a
-- RESTRICTIVE row-level-security policy per write verb, binding `ironauth_control`
-- to the ONE reserved name the management surface addresses. Restrictive policies
-- AND with the permissive isolation policy rather than replacing it, and they name
-- `ironauth_control` alone, so the data-plane role and the owner are untouched.
--
-- SELECT is deliberately NOT restricted. 0035 granted the control role SELECT here
-- for the config-promotion plan's reference-PRESENCE check, which asks about secrets
-- by whatever name a variable references; narrowing the read to one name would break
-- that, and the read was never the hole. The hole was the write.
--
-- The name is spelled as a literal here and lives as
-- `ironauth_admin::migration::OUTBOUND_VERIFICATION_SECRET_NAME` in the code. The two
-- cannot be made one constant across the language boundary; what stops them drifting
-- is that a drift makes every control-plane write fail closed, loudly, in
-- `crates/ironauth-admin/tests/outbound_verification.rs` on the first arming.
--
-- Row-level security is unchanged and still FORCED: every statement runs inside the
-- scoped transaction that binds `ironauth.tenant_id` and `ironauth.environment_id`,
-- so a control-plane write lands in exactly the addressed environment or in none.
--
-- Expand-only and safe for the old binary: additive grants plus policies that
-- constrain a role which, before this migration, could not write here at all. A
-- binary that predates this migration simply never issues the statements it permits.

GRANT INSERT, DELETE ON environment_secrets TO ironauth_control;
GRANT UPDATE (ciphertext, dek_version, version, updated_at)
    ON environment_secrets TO ironauth_control;

-- The control plane may write exactly ONE reserved name, and only in its bound scope
-- (the isolation policy from 0034 still applies and these AND with it). Three
-- policies rather than one FOR ALL, because FOR ALL would put a USING clause on
-- SELECT too and break 0035's reference-presence read.
CREATE POLICY environment_secrets_control_writes_one_reserved_name_insert
    ON environment_secrets
    AS RESTRICTIVE
    FOR INSERT
    TO ironauth_control
    WITH CHECK (name = 'ironauth.outbound_verification_token');

CREATE POLICY environment_secrets_control_writes_one_reserved_name_update
    ON environment_secrets
    AS RESTRICTIVE
    FOR UPDATE
    TO ironauth_control
    USING (name = 'ironauth.outbound_verification_token')
    WITH CHECK (name = 'ironauth.outbound_verification_token');

CREATE POLICY environment_secrets_control_writes_one_reserved_name_delete
    ON environment_secrets
    AS RESTRICTIVE
    FOR DELETE
    TO ironauth_control
    USING (name = 'ironauth.outbound_verification_token');
