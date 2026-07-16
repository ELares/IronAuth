-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Migrations as an invariant-checked state machine (issue #59, exploratory).
--
-- A long-running data migration (a streaming bulk import, a schema migration job,
-- and, by design, a tenant move) is today a fire-and-forget job: nothing
-- structurally stops an operator declaring victory while inconsistent identities
-- still exist. This migration lands the persistent state for wrapping such a job in
-- an explicit, invariant-checked state machine. Two new tenant-scoped tables:
--
--   1. `migration_runs`: one row per wrapped migration. It carries the NAMED state
--      the run walks (defined -> validating -> running -> reconciling ->
--      complete | abandoned), the ground-truth `source_total` the count invariant
--      measures against, the `backfill_expected` the sentinel invariant measures
--      against, an optional non-PII `subject_ref` back to the underlying job (a
--      `tmj_` schema-migration-job id, or an operator-chosen import label), and the
--      operator-safe `abandoned_reason` recorded on an explicit abandonment. The
--      state is a POINTER only; every invariant verdict is RE-EVALUATED from the
--      record table below at check time, never cached on this row, so a verdict
--      cannot drift from the data and survives a process restart intact.
--
--   2. `migration_run_records`: one row per source record the run touched. `outcome`
--      is the closed accounting bucket (imported | failed | skipped) the count
--      invariant sums; `consistent` is false for an identity in an inconsistent
--      state (failed transform, failed re-validation, missing credential material)
--      the consistency invariant forbids at completion; `backfilled` is the sentinel
--      the backfill invariant requires set. The record's natural subject (a `usr_`
--      id, or a bulk-import record key that MAY be end-user PII) is NEVER stored in
--      the clear: it lands as a blind index (`subject_bidx`, for lookup and
--      per-run dedup) and a sealed value (`subject_sealed`, opened only for an
--      authorized operator view), exactly the envelope discipline issue #48
--      established. `detail` is an operator-safe reason (RFC 6901 JSON Pointer
--      reasons, an outcome note), never an offending value, so it carries no PII.
--
-- Migration safety obligation (see migrate.rs): the two NEW tenant-scoped tables
-- each ENABLE and FORCE row-level security, add the (tenant, environment) isolation
-- policy, add the nonempty-scope CHECK, use COLUMN-scoped least-privilege grants
-- (the #31 lesson), and are registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The wrapped-migration state machine row.
--
-- id is a `mgr_` scoped identifier (embeds its (tenant, environment)), so a run id
-- minted in one scope parses as a uniform not-found under another. kind is the closed
-- wrapped-workload type. state is the closed lifecycle pointer. source_total is the
-- authoritative denominator the count invariant re-derives against; backfill_expected
-- is the number of records the sentinel invariant requires marked. subject_ref links
-- the run to its underlying job (a `tmj_` id or an operator import label) and is
-- non-PII. abandoned_reason is the operator-safe justification recorded on an
-- explicit `-> abandoned` transition; NULL for a run that was never abandoned.
CREATE TABLE migration_runs (
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The closed wrapped-workload type: a streaming bulk import (issue #55) or a
    -- schema migration job (issue #53). A tenant move (M5) fits the same model and
    -- is a documented future value, deliberately not in the closed set until wired.
    kind              text        NOT NULL,
    -- The closed lifecycle POINTER. A verdict is never stored here; `complete` is
    -- reachable only when every invariant re-evaluates satisfied.
    state             text        NOT NULL DEFAULT 'defined',
    -- The ground-truth source record count the count invariant measures against.
    source_total      bigint      NOT NULL DEFAULT 0,
    -- The number of records a backfill must mark; the sentinel invariant measures
    -- the marked population against this.
    backfill_expected bigint      NOT NULL DEFAULT 0,
    -- A non-PII link back to the wrapped job: a `tmj_` schema-migration-job id, or an
    -- operator-chosen import label. Never end-user data.
    subject_ref       text,
    -- The operator-safe reason recorded on an explicit abandonment; NULL otherwise.
    abandoned_reason  text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT migration_runs_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT migration_runs_kind_known
        CHECK (kind IN ('bulk_import', 'schema_migration')),
    CONSTRAINT migration_runs_state_known
        CHECK (state IN ('defined', 'validating', 'running', 'reconciling', 'complete', 'abandoned')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The operator list view pages runs newest-stable-first, keyed by (created_at, id).
CREATE INDEX migration_runs_scope_idx
    ON migration_runs (tenant_id, environment_id, created_at, id);

ALTER TABLE migration_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_runs_tenant_isolation ON migration_runs
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Both planes create and read runs and drive their transitions. The immutable
-- definition columns (id, tenant_id, environment_id, kind, created_at) are never
-- updated, so the UPDATE grant is COLUMN-scoped to exactly the mutable lifecycle
-- columns, never a table-wide UPDATE (the #31 lesson).
GRANT SELECT, INSERT ON migration_runs TO ironauth_app, ironauth_control;
GRANT UPDATE (
        state, source_total, backfill_expected, subject_ref, abandoned_reason, updated_at
    ) ON migration_runs TO ironauth_app, ironauth_control;

-- ---------------------------------------------------------------------------
-- 2. The per-record accounting and consistency ledger.
--
-- id is a `mrr_` scoped identifier. run_id is the owning run. The natural subject is
-- stored ONLY as a blind index (subject_bidx, the lookup/dedup key) and a sealed value
-- (subject_sealed, opened for the authorized operator view) under subject_dek_version
-- (issue #48): a record key can be end-user PII, so no plaintext identifier ever lands
-- on a column. outcome is the closed accounting bucket the count invariant sums.
-- consistent is false for an identity in an inconsistent state the consistency
-- invariant forbids at completion. backfilled is the sentinel the backfill invariant
-- requires set. detail is an operator-safe reason (JSON Pointer reasons, an outcome
-- note), never an offending value, so it carries no PII.
CREATE TABLE migration_run_records (
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    run_id             text        NOT NULL,
    -- The blind index of the record's natural subject, the value an equality lookup
    -- and the per-run dedup index query against. A keyed per-tenant HMAC tag, never a
    -- bare hash, so the same subject in two tenants maps to two different tags.
    subject_bidx       bytea       NOT NULL,
    -- The record's natural subject SEALED under the scope DEK; opened only for an
    -- authorized operator view. A record key can be end-user PII, so it never lands
    -- plaintext.
    subject_sealed     bytea       NOT NULL,
    -- The DEK version that sealed subject_sealed.
    subject_dek_version integer    NOT NULL,
    -- The closed accounting bucket the count invariant sums against source_total.
    outcome            text        NOT NULL,
    -- Whether the identity is in a CONSISTENT state; the consistency invariant forbids
    -- any false row at completion.
    consistent         boolean     NOT NULL DEFAULT true,
    -- The backfill SENTINEL; the backfill invariant forbids any false row at completion.
    backfilled         boolean     NOT NULL DEFAULT false,
    -- An operator-safe reason (JSON Pointer reasons, an outcome note); never an
    -- offending value, so no PII.
    detail             text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT migration_run_records_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT migration_run_records_outcome_known
        CHECK (outcome IN ('imported', 'failed', 'skipped')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (run_id) REFERENCES migration_runs (id)
);

-- The invariant evaluators and the paginated violation view scan a run's records by
-- (run_id, id); the ordering key gives a stable cursor page.
CREATE INDEX migration_run_records_run_idx
    ON migration_run_records (tenant_id, environment_id, run_id, id);
-- A subject is accounted at most once per run: a second row for the same subject in a
-- run is refused, so a double-count cannot silently satisfy the count invariant.
CREATE UNIQUE INDEX migration_run_records_run_subject_unique
    ON migration_run_records (tenant_id, environment_id, run_id, subject_bidx);

ALTER TABLE migration_run_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_run_records FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_run_records_tenant_isolation ON migration_run_records
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Both planes ingest and read records; reconciliation and the backfill pass flip the
-- consistent / backfilled / detail columns. The immutable accounting columns (subject
-- and outcome) are never updated, so the UPDATE grant is COLUMN-scoped to exactly the
-- reconciliation columns, never a table-wide UPDATE (the #31 lesson).
GRANT SELECT, INSERT ON migration_run_records TO ironauth_app, ironauth_control;
GRANT UPDATE (consistent, backfilled, detail)
    ON migration_run_records TO ironauth_app, ironauth_control;
