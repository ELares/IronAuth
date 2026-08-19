-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Bring two scope foreign keys onto the naming convention the absent-scope conversion
-- depends on (issues #111, #112). They were never on it: both were declared off-convention
-- and have been since the migration that created them.
--
-- WHAT WAS WRONG. `StoreError::from` recognizes "this write tripped a foreign key onto a
-- scope table" by the constraint NAME, matching the suffix `_tenant_id_fkey`. That works
-- because every scoped table declares the key as
--
--     FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
--
-- which Postgres auto-names `<table>_environment_id_tenant_id_fkey`. `message_templates`
-- (0145) and `flow_targets` (0146) wrote the same key with the columns in the OTHER order,
-- so Postgres named them `<table>_tenant_id_environment_id_fkey`, ending in
-- `_environment_id_fkey`. The rule does not match, and a write into an environment that
-- does not exist answers a SERVER FAULT instead of the uniform not-found.
--
-- WHAT THAT IS AND IS NOT, stated precisely because the first version of this header
-- overstated it. Both tables are CONTROL-PLANE only: 0145 and 0146 grant the data-plane
-- role SELECT and nothing else, and no crate outside `ironauth-store` references either
-- one, so no route reaches these writes today on any plane. The uniform not-found exists
-- to stop the data plane being an existence oracle, and these two are not on it.
--
-- So this is not a live oracle, and it is not a live 500 either: with no route to these
-- writes, nobody gets either answer today. What it is, is a table that BROKE the convention
-- the anti-oracle conversion is built on. The day such a table acquires a management write
-- path it is issue #409's contract defect (an integrator who mistypes an environment id
-- gets a 500); the day it acquires a data-plane one it is issue #449's oracle. The
-- completeness guard is what caught it, and the guard is worth exactly as much as the
-- convention being kept.
--
-- WHY RE-DECLARE RATHER THAN RENAME. `ALTER ... RENAME CONSTRAINT` would satisfy the rule
-- while leaving the columns in the order the name now denies, so the schema would agree
-- with the matcher and lie to the reader. Dropping and re-adding with the conventional
-- order makes the name true again, and lets Postgres derive it rather than this file
-- asserting it -- which is the property that keeps the next table honest too.
--
-- IT IS NOT FREE, and the alternative was. A DROP of a foreign key takes
-- AccessExclusiveLock on the REFERENCED table, so this holds one on `environments` through
-- the re-added key's validating scan; `RENAME CONSTRAINT` touches `environments` not at
-- all. MEASURED: with this body mid-flight in one transaction, a plain
-- `SELECT count(*) FROM environments` from another connection blocks. Both tables are
-- small per-environment configuration, so the scan is short, but the lock request queues
-- behind any in-flight reader and blocks every new one while it waits. `lock_timeout`
-- below turns that from an unbounded stall into a failed migration an operator can retry.
--
-- Widening the recognition rule instead was the third option and is decisively unsound:
-- measured against the live schema, `_environment_id_fkey` would newly match TEN
-- constraints and all ten point at a non-scope parent (grants, sessions, clients,
-- custom_domains, refresh_families), so ten classes of genuine referential failure would
-- start answering not-found for a row the caller can address.
--
-- Both tables carry `ON DELETE CASCADE`, preserved exactly.

-- Bounded rather than unbounded: if `environments` is busy, fail and let the operator
-- retry rather than queue an AccessExclusive request in front of every new reader.
--
-- TUNABLE, because `SET LOCAL` overrides a role or database default and this file is
-- CHECKSUMMED, so a bare literal would be a one-way choice nobody could revisit. An
-- operator on a busy `environments` sets `ironauth.migration_lock_timeout` (in
-- postgresql.conf, on the role, or on the connection) and gets their value; everyone else
-- gets three seconds. The `true` argument to `current_setting` makes an unset custom
-- setting return NULL rather than raise, which is what makes the default reachable at all.
--
-- `set_config(..., true)` rather than `SET LOCAL`, because `SET` takes a literal and not an
-- expression: the expression form is a syntax error, which is how this was found.
DO $$
BEGIN
    PERFORM set_config(
        'lock_timeout',
        coalesce(current_setting('ironauth.migration_lock_timeout', true), '3s'),
        true
    );
END
$$;

ALTER TABLE message_templates
    DROP CONSTRAINT message_templates_tenant_id_environment_id_fkey;

ALTER TABLE message_templates
    ADD FOREIGN KEY (environment_id, tenant_id)
        REFERENCES environments (id, tenant_id) ON DELETE CASCADE;

ALTER TABLE flow_targets
    DROP CONSTRAINT flow_targets_tenant_id_environment_id_fkey;

ALTER TABLE flow_targets
    ADD FOREIGN KEY (environment_id, tenant_id)
        REFERENCES environments (id, tenant_id) ON DELETE CASCADE;
