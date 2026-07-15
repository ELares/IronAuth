-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- JSON Schema identity traits with versioning and migration jobs (issue #53).
--
-- Traits are the custom user profile fields (name, address, phone, and arbitrary
-- tenant-defined fields) beyond the standard OIDC claims. They are validated
-- against a per (tenant, environment) JSON Schema (draft 2020-12), the schema
-- EVOLVES through immutable versions, and an incompatible evolution runs a
-- MIGRATION JOB that transforms and re-validates existing identities. This
-- migration lands the three pieces of persistent state that layer needs:
--
--   1. A NEW tenant-scoped `trait_schemas` registry: one row per immutable schema
--      VERSION in a scope. `schema_json` is the JSON Schema document (draft
--      2020-12), which also carries the IronAuth behavior annotations (which field
--      is a login identifier, a verification address, a recovery channel, or
--      admin-only). A schema definition is NOT end-user PII, so it is stored in the
--      clear. `status` is the active-pointer: at most one version per scope is
--      `active` (the served default), enforced by a partial unique index; every
--      other version is a `candidate`. A version's CONTENT is immutable once
--      written (only its status pointer moves), so the registry is append-only in
--      substance.
--
--   2. A NEW tenant-scoped `trait_migration_jobs` table: the Postgres-backed job
--      substrate (IronBus is an optional accelerator, never required: covenant). A
--      job is a dry-run (validate every identity against a candidate version,
--      mutating nothing) or a migrate (apply a declarative transform, then
--      re-validate, writing the new trait document and version). A job is
--      deterministic, idempotent, resumable (a `cursor_id` records progress so a
--      crash mid-run resumes without double-migrating), and per (tenant,
--      environment) scoped. `failures_json` carries the per-record failure report
--      (each an identity subject plus RFC 6901 JSON Pointer reasons, never a trait
--      value, so the report carries no PII).
--
--   3. Three additive `users` columns: `traits_sealed` (the trait document sealed
--      under the scope's envelope DEK, issue #48: trait data is user profile PII and
--      never lands on a plaintext column), `traits_dek_version` (the DEK version
--      that sealed it), and `traits_schema_version` (the schema version the
--      identity's traits were last validated against, so a migration job can select
--      exactly the identities still on an older version).
--
-- Migration safety obligation (see migrate.rs): the two NEW tenant-scoped tables
-- (trait_schemas, trait_migration_jobs) each ENABLE and FORCE row-level security,
-- add the (tenant, environment) isolation policy, add the nonempty-scope CHECK, and
-- are registered in scripts/query-audit.sh. The users columns are additive nullable
-- columns with a column-scoped grant (never a table-wide UPDATE, the #31 lesson).
-- Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The per (tenant, environment) versioned trait-schema registry.
--
-- id is a `tsc_` scoped identifier (embeds its (tenant, environment)), so a schema
-- id minted in one scope parses as a uniform not-found under another. version is the
-- per-scope monotonic version number a new version increments. schema_json is the
-- JSON Schema document (draft 2020-12), carrying the behavior annotations inline;
-- it is validated well formed at the application layer before insert. status is the
-- active-pointer, closed to (candidate, active) by a CHECK.
CREATE TABLE trait_schemas (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The per-scope monotonic version number (1, 2, 3, ...).
    version        integer     NOT NULL,
    -- The JSON Schema document (draft 2020-12) plus inline behavior annotations. A
    -- schema definition is not end-user PII, so it is stored in the clear.
    schema_json    text        NOT NULL,
    -- The active-pointer: at most one `active` version per scope (partial unique
    -- index below); every other version is a `candidate`.
    status         text        NOT NULL DEFAULT 'candidate',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trait_schemas_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT trait_schemas_version_positive
        CHECK (version >= 1),
    CONSTRAINT trait_schemas_status_known
        CHECK (status IN ('candidate', 'active')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A version number is unique per scope: a second row claiming the same version in a
-- scope is refused. Scope-keyed, so the same version number in two scopes is two
-- distinct rows.
CREATE UNIQUE INDEX trait_schemas_scope_version_unique
    ON trait_schemas (tenant_id, environment_id, version);

-- At most ONE active version per scope: the served default. A second activation in a
-- scope must first demote the prior active (done in one transaction by the
-- repository), so this partial unique index can never hold two active rows.
CREATE UNIQUE INDEX trait_schemas_scope_active_unique
    ON trait_schemas (tenant_id, environment_id)
    WHERE status = 'active';

ALTER TABLE trait_schemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE trait_schemas FORCE ROW LEVEL SECURITY;
CREATE POLICY trait_schemas_tenant_isolation ON trait_schemas
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Both planes read and create schema versions (the data plane validates a trait
-- write against the active schema; the management plane registers and activates
-- versions), and both may move the status POINTER at activation. The status is the
-- only mutable column (a version's content is immutable), so the UPDATE grant is
-- COLUMN-scoped to status alone, never a table-wide UPDATE (the #31 lesson).
GRANT SELECT, INSERT ON trait_schemas TO ironauth_app, ironauth_control;
GRANT UPDATE (status) ON trait_schemas TO ironauth_app, ironauth_control;

-- ---------------------------------------------------------------------------
-- 2. The Postgres-backed trait migration / dry-run job substrate.
--
-- id is a `tmj_` scoped identifier. kind is the closed job type. from_version and
-- to_version bound the evolution (validate/migrate FROM one version TO a candidate).
-- transform_json is the declarative field mapping (rename/default/drop) a migrate
-- applies before re-validating; a dry-run leaves it the empty program. status walks
-- the closed lifecycle. cursor_id is the last processed identity id, so a resumed
-- run continues past it (resumability). The *_count columns and failures_json are
-- the progress and per-record failure report the management API observes;
-- failures_json carries identity subjects and JSON Pointer reasons, never a trait
-- value, so a job row carries no PII.
CREATE TABLE trait_migration_jobs (
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The closed job type: validate only (dry_run) or transform + re-validate + write.
    kind            text        NOT NULL,
    -- The schema version identities are migrated / validated FROM.
    from_version    integer     NOT NULL,
    -- The candidate schema version identities are validated / migrated TO.
    to_version      integer     NOT NULL,
    -- The declarative transform program (a JSON array of rename/default/drop steps),
    -- applied in order by a migrate; the empty program for a dry_run.
    transform_json  text        NOT NULL DEFAULT '[]',
    -- The closed lifecycle: pending -> running -> completed | failed.
    status          text        NOT NULL DEFAULT 'pending',
    -- The last processed identity id (resumability); NULL before the first batch.
    cursor_id       text,
    -- Progress and outcome counters, observable through the management API.
    total_count     bigint      NOT NULL DEFAULT 0,
    processed_count bigint      NOT NULL DEFAULT 0,
    migrated_count  bigint      NOT NULL DEFAULT 0,
    failure_count   bigint      NOT NULL DEFAULT 0,
    -- The per-record failure report: identity subjects and RFC 6901 JSON Pointer
    -- reasons, never a trait value (no PII).
    failures_json   text        NOT NULL DEFAULT '[]',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trait_migration_jobs_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT trait_migration_jobs_kind_known
        CHECK (kind IN ('dry_run', 'migrate')),
    CONSTRAINT trait_migration_jobs_status_known
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX trait_migration_jobs_scope_idx
    ON trait_migration_jobs (tenant_id, environment_id, created_at, id);
-- The activation cutover looks up the latest completed job targeting a version.
CREATE INDEX trait_migration_jobs_scope_target_idx
    ON trait_migration_jobs (tenant_id, environment_id, to_version);

ALTER TABLE trait_migration_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE trait_migration_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY trait_migration_jobs_tenant_isolation ON trait_migration_jobs
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Both planes create and read jobs and advance them a batch at a time. The advancing
-- worker rewrites exactly the lifecycle / progress columns, so the UPDATE grant is
-- COLUMN-scoped to those, never a table-wide UPDATE (the #31 lesson). The immutable
-- job definition (kind, versions, transform) is never updated.
GRANT SELECT, INSERT ON trait_migration_jobs TO ironauth_app, ironauth_control;
GRANT UPDATE (
        status, cursor_id, processed_count, migrated_count, failure_count,
        failures_json, updated_at
    ) ON trait_migration_jobs TO ironauth_app, ironauth_control;

-- ---------------------------------------------------------------------------
-- 3. The per-user sealed trait document and its version stamp, folded onto users.
--
-- traits_sealed is the trait JSON document sealed under the scope's envelope DEK
-- (issue #48): trait data is user profile PII, so the plaintext never lands on a
-- column. traits_dek_version is the DEK version that sealed it. traits_schema_version
-- is the schema version the identity's traits were last validated against, so a
-- migration job selects exactly the identities still on an older version. All three
-- are nullable: an identity with no traits set has all three NULL.
ALTER TABLE users
    ADD COLUMN traits_sealed         bytea,
    ADD COLUMN traits_dek_version    integer,
    ADD COLUMN traits_schema_version integer;

-- Both planes write a user's traits (self-service and admin) and a migration job
-- rewrites them on migrate, so the UPDATE grant is COLUMN-scoped to exactly the
-- three trait columns, never a table-wide UPDATE (the #31 lesson).
GRANT UPDATE (traits_sealed, traits_dek_version, traits_schema_version)
    ON users TO ironauth_app, ironauth_control;
