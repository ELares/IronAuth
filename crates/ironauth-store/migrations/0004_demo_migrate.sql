-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Expand-contract worked example, phase 2 of 3: MIGRATE (issue #7).
--
-- Backfill the new column from the old one for every existing row. After this
-- step the new binary can read `display_name` for all rows, so it becomes safe
-- to stop reading `legacy_name`. This is idempotent (the WHERE guard skips rows
-- already backfilled), which a backfill should be so it can be re-run safely.

UPDATE migration_demo
   SET display_name = legacy_name
 WHERE display_name IS NULL;
