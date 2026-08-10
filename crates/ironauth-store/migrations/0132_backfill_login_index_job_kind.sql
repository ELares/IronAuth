-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Admit the login-index BACKFILL as a third trait-job kind (issue #624).
--
-- 0038 pinned `trait_migration_jobs.kind` to the two kinds that existed then, `dry_run` and
-- `migrate`, with a named CHECK. That constraint did its job: adding the variant in Rust
-- without touching the database failed the job create at the constraint rather than writing
-- a row nothing could interpret. This widens it to the three kinds that exist now.
--
-- The backfill is a third KIND rather than a flag on `migrate` because it validates nothing
-- and transforms nothing. It reindexes the traits already stored, so an identity whose
-- document no longer satisfies the active schema is still indexed; a `migrate` would refuse
-- that record and leave the person unable to log in through a field their operator
-- published.
--
-- EXPAND only. The constraint is REPLACED rather than relaxed in place because Postgres has
-- no "alter check": the drop and the add are one transaction, so no window exists in which
-- the column is unconstrained. Every existing row already satisfies the new predicate,
-- because the new one admits a strict superset of the old.
ALTER TABLE trait_migration_jobs DROP CONSTRAINT trait_migration_jobs_kind_known;
ALTER TABLE trait_migration_jobs ADD CONSTRAINT trait_migration_jobs_kind_known
    CHECK (kind IN ('dry_run', 'migrate', 'backfill_login_index'));
