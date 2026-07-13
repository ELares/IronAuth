-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Expand-contract worked example, phase 1 of 3: EXPAND (issue #7).
--
-- This migration set (0003 expand, 0004 migrate, 0005 contract) is the checked
-- example that exercises all three phases end to end in CI. It operates ONLY on
-- a throwaway demo object, `migration_demo`, so it demonstrates the framework
-- without changing the meaning of the real schema. `migration_demo` is not
-- tenant-scoped (it holds no tenant data), so the tenant-isolation obligations
-- that apply to scoped tables do not apply to it; a real tenant-scoped table
-- added by a migration MUST instead set up forced row-level security, the
-- isolation policy, and the nonempty-scope CHECK, as 0002 does for audit_log.
--
-- The worked scenario is a column rename done safely: a table starts with a
-- `legacy_name` column, we ADD a nullable `display_name` column (this expand
-- step, additive and safe for an old binary that ignores it), the next migration
-- backfills it, and the contract step drops `legacy_name`.

CREATE TABLE migration_demo (
    id          text PRIMARY KEY,
    legacy_name text NOT NULL
);

-- Seed one row so the backfill in phase 2 has data to migrate, keeping the
-- example self-contained and verifiable in a single forward run.
INSERT INTO migration_demo (id, legacy_name) VALUES ('demo-1', 'alpha');

-- EXPAND: add the new column as nullable (additive). The old binary neither
-- reads nor writes it, so both versions coexist.
ALTER TABLE migration_demo ADD COLUMN display_name text;
