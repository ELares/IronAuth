-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Expand-contract worked example, phase 3 of 3: CONTRACT (issue #7).
--
-- Once no binary reads `legacy_name`, remove it. This is the destructive step,
-- deliberately last and in its own migration so it only runs after the expand
-- and migrate steps are recorded as applied. After this migration the demo table
-- carries only `display_name`; the migration-framework test asserts that
-- `legacy_name` is gone and `display_name` was backfilled, proving the full
-- forward chain and the contract removal.

ALTER TABLE migration_demo DROP COLUMN legacy_name;
