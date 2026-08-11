-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Audit stream separation, EXPAND phase (issue #109).
--
-- Migration 0002 carried the audit envelope and said explicitly that the OCSF
-- mapping and the auth-stream versus admin-stream separation were M11's job.
-- This is that job's storage half: one column naming which stream a row belongs
-- to, so the two streams can be retained, exported, and queried independently
-- without a reader having to re-derive the classification from the action text.
--
-- The value is NOT computed in SQL. It is written by the single audited-write
-- primitive from `ocsf::class_for(action).stream()`, so there is exactly one
-- classification in the system and Postgres never holds a second copy of the
-- domain tables that could drift from the Rust ones.
--
-- NULLABLE here, and that is the whole reason this is a separate migration from
-- the backfill in 0134. This file must be safe for the PREVIOUS binary to
-- ignore, which is what the Expand phase means. The previous binary's INSERT
-- does not bind `stream`; a NOT NULL column would make every audit write it
-- attempts fail, and because every mutation writes its audit row in the same
-- transaction, that is not a degraded audit trail, it is every mutation on
-- every not-yet-rolled pod failing. The column is tightened to NOT NULL in
-- 0134, once the binary that populates it is the one running.
--
-- Adding a nullable column with no default is a catalog-only change: no table
-- rewrite and no long lock, which matters because audit_log is the table that
-- grows without bound.

ALTER TABLE audit_log ADD COLUMN stream text;

-- NULL is permitted (a row from before the split, or from a pre-rollout binary)
-- but a WRONG value is not. A row filed under a stream nothing retains and
-- nothing exports has silently left the trail, and unlike a NULL it does not
-- look like anything is missing.
ALTER TABLE audit_log ADD CONSTRAINT audit_log_stream_known
    CHECK (stream IS NULL OR stream IN ('admin_action', 'authentication'));
