-- How each directory connector's last sync went (issue #142).
--
-- The isolation is already real: one unreachable server degrades only its own connector and the
-- server keeps running. What has been missing is the OTHER half of that criterion -- an operator
-- being able to SEE it. Until now a connector nobody can bind to produced a warning in a log
-- line, which is not a surface: nothing can be alerted on it, no console can show it, and the
-- question "which of my directories is broken right now" has no answer.
--
-- ONE ROW PER CONNECTOR, replaced each pass. This is health, not history: the question is "is
-- this directory syncing", and a run log answering "was it syncing at 04:00 last Tuesday" is a
-- different feature with different retention. The audit log and the emitted events already carry
-- what changed; this carries whether the last attempt worked.
--
-- CONSECUTIVE FAILURES IS A COLUMN, not something a reader derives. With one row per connector
-- there is no history to count from, and the count is what distinguishes a directory that
-- blipped once from one that has been down for a day. It is also what makes "recovery resumes
-- sync without manual intervention" observable: the counter returns to zero on the first pass
-- that succeeds, with nobody clearing anything.
--
-- THE REASON IS A CATEGORY, NOT THE MESSAGE. A failure's Display can carry a DN, a URL, or a
-- server-supplied diagnostic -- `SyncError::Mapping { dn, .. }` and `DuplicateStableId { dns }`
-- both interpolate one -- and a DN carries a person's name and their place in an organization.
-- The sibling snapshot table seals identifiers for exactly that reason, and an unsealed column
-- beside it holding the same text would give that seal away. So the writer maps the failure to a
-- fixed phrase naming its KIND, and the full message goes to the log, where retention and access
-- are already decided. The length ceiling then bounds what a future writer can put here at all.
--
-- Expand-only: a new table with no writer on any older binary.

CREATE TABLE ldap_sync_runs (
    -- The `ldc_` connector. One row per connector, so the connector is the key.
    connector_id        text        NOT NULL PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,

    -- When the pass reached this connector, and how long it took end to end.
    started_at          timestamptz NOT NULL,
    duration_ms         bigint      NOT NULL,

    -- How it ended: the sweep's own vocabulary, closed at the database so a typo cannot
    -- invent a health state nothing renders.
    outcome             text        NOT NULL,
    -- The short reason, for every outcome that is not `planned`.
    error               text,

    -- What the pass wrote for this connector.
    provisioned         integer     NOT NULL DEFAULT 0,
    already_present     integer     NOT NULL DEFAULT 0,
    deactivated         integer     NOT NULL DEFAULT 0,
    deleted             integer     NOT NULL DEFAULT 0,
    already_absent      integer     NOT NULL DEFAULT 0,
    already_removed     integer     NOT NULL DEFAULT 0,
    -- Per-principal failures inside an otherwise successful pass. A connector can be reachable
    -- and still be failing to apply, which is a different unhealthy from a bad bind.
    apply_failures      integer     NOT NULL DEFAULT 0,

    -- Passes in a row that did not produce a plan, zeroed by the first that does.
    consecutive_failures integer    NOT NULL DEFAULT 0,
    -- The last time this connector DID produce a plan, so an operator can see how stale the
    -- directory's view is rather than only that the last attempt failed.
    last_success_at     timestamptz,

    CONSTRAINT ldap_sync_runs_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT ldap_sync_runs_outcome_closed
        CHECK (outcome IN ('planned', 'unreachable', 'failed', 'timed_out', 'skipped')),
    -- An outcome that is not `planned` has to say why; `planned` has nothing to say.
    CONSTRAINT ldap_sync_runs_error_matches_outcome
        CHECK ((outcome = 'planned') = (error IS NULL)),
    CONSTRAINT ldap_sync_runs_error_bounded
        CHECK (error IS NULL OR (error <> '' AND octet_length(error) <= 512)),
    CONSTRAINT ldap_sync_runs_counts_nonnegative
        CHECK (provisioned >= 0 AND already_present >= 0 AND deactivated >= 0 AND deleted >= 0
               AND already_absent >= 0 AND already_removed >= 0 AND apply_failures >= 0
               AND consecutive_failures >= 0 AND duration_ms >= 0),
    -- A run that produced a plan IS the last success, so the two cannot disagree.
    CONSTRAINT ldap_sync_runs_success_is_consistent
        CHECK (outcome <> 'planned' OR (consecutive_failures = 0 AND last_success_at IS NOT NULL)),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Health dies with the connector it describes.
    FOREIGN KEY (connector_id) REFERENCES ldap_connectors (id) ON DELETE CASCADE
);

-- The console lists every connector in a scope.
CREATE INDEX ldap_sync_runs_by_scope_idx
    ON ldap_sync_runs (tenant_id, environment_id);
-- And "which of my directories is unhealthy" is its own read. THE PREDICATE IS BOTH HALVES: a
-- connector that binds fine and fails to apply every principal is unhealthy too, and an index on
-- `consecutive_failures` alone would silently omit exactly that case -- which is the one the
-- health surface exists to make visible.
CREATE INDEX ldap_sync_runs_unhealthy_idx
    ON ldap_sync_runs (tenant_id, environment_id)
    WHERE consecutive_failures > 0 OR apply_failures > 0;

ALTER TABLE ldap_sync_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_sync_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY ldap_sync_runs_scope ON ldap_sync_runs
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The sweep writes it and the management plane reads it; both are the control role. No DELETE:
-- health is removed by removing its connector, which cascades. A standalone delete would be a way
-- to make a failing directory look like one nobody has swept yet.
GRANT SELECT, INSERT ON ldap_sync_runs TO ironauth_control;
GRANT UPDATE (started_at, duration_ms, outcome, error, provisioned, already_present, deactivated,
              deleted, already_absent, already_removed, apply_failures, consecutive_failures,
              last_success_at)
    ON ldap_sync_runs TO ironauth_control;

-- The DATA plane gets NOTHING, for the reason 0212 gives about the connector row: no request path
-- reads directory health, and it names hosts and bind failures.
