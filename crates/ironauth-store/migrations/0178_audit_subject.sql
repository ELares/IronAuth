-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The HUMAN an audit row is about, when the row is about one (issue #130, criterion 2).
--
-- The criterion asks for events "attributable to the agent AND its linked user AND
-- organization". Two of those three already had a home: the target column names the agent,
-- and migration 0138 added `organization_id` for the per-organization SIEM streams. The
-- linked user had none, so the shipped OCSF event could not name it, and an investigator
-- handed `agent_token.issue` had to join back through the agent's registration row to find
-- out which person the machine was acting for. "Attributable through a second lookup" is not
-- what the criterion says.
--
-- WHY A COLUMN RATHER THAN THE DETAIL STRING. `detail` is a free-text operator-safe
-- dimension, and a consumer reading a user id out of it would be parsing prose. This is an
-- identifier a stream selects on and a SIEM correlates by, so it is a column with the same
-- shape as the organization one beside it.
--
-- NOT IN THE CHAIN'S CANONICAL FORM. `ChainedAuditRow::canonical` is the hash input for
-- `audit_chain`, and adding a field to it would make every entry sealed under the old shape
-- fail to recompute. The column is therefore carried on the row and rendered into the shipped
-- event, and deliberately left out of the canonical JSON; the Rust says so at both sites.
-- What the chain seals is unchanged, which is the point: this adds a dimension to delivery,
-- not to the tamper-evidence.
--
-- NULLABLE, and NULL is a fact rather than missing data: it means "this row is not about a
-- person". Most rows are not. A NOT NULL default would force every existing and future write
-- site to name a user it does not have, which is how a column ends up holding a placeholder
-- that a consumer then filters on.

ALTER TABLE audit_log ADD COLUMN subject_id text;

COMMENT ON COLUMN audit_log.subject_id IS
    'Issue #130: the human this row is about, when it is about one. NULL means the row is '
    'not about a person, which is a fact rather than an omission. Deliberately absent from '
    'the audit_chain canonical form, so adding it did not invalidate any sealed entry.';

-- The index a SIEM correlation reads: everything about one person, newest first. Partial,
-- because the column is NULL on most rows and an index over those entries would be almost
-- entirely dead weight.
CREATE INDEX audit_log_subject_idx
    ON audit_log (tenant_id, environment_id, subject_id, occurred_at DESC)
    WHERE subject_id IS NOT NULL;
