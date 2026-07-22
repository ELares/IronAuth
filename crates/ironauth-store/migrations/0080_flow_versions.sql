-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The custom-journey version registry and its per-journey active pin (issue #92, PR 5).
--
-- A custom (declarative) journey is authored as a canonical Journey artifact and stored as an
-- immutable, append-only VERSION. A live custom flow runs against the version it was created
-- against (stamped on flows.flow_version_id, added nullable in 0079), never against whichever
-- version is pinned mid-flow. This migration lands the two tables that layer needs and closes
-- the deferred foreign key from the flow row:
--
--   flow_versions: one row per immutable journey VERSION in a scope. It holds:
--     - a scope embedded `flv_` id (embeds its (tenant, environment), so a version id minted in
--       one scope parses as a uniform not found under another);
--     - journey_id: the author-facing journey identifier the version belongs to (the promotion /
--       diff key together with version). Stable across a journey's versions;
--     - version: the per-scope, per-journey_id monotonic version number a new version increments
--       (1, 2, 3, ...). Unique per (tenant, environment, journey_id);
--     - artifact: the canonical Journey JSON (a jsonb document). Validated LOAD-VALID at write
--       time (ironauth_journey::validate + compile) before it is stored, so a stored artifact is
--       always already a compilable journey. It carries NO secret by construction: a predicate
--       references trait POINTERS and group / scope NAMES, never values;
--     - created_by: the actor ref that authored the version (operator-safe provenance);
--     - created_at.
--   A version's CONTENT is immutable once written (a change is a NEW version), so the registry is
--   append-only: no UPDATE and no DELETE grant.
--
--   flow_version_pins: one row per (tenant, environment, journey_id): the ACTIVE version a fresh
--   custom flow of that journey is created against. It holds a scope embedded `fvp_` id, the
--   journey_id (the per-scope natural key, unique per scope), and flow_version_id (the pinned
--   version's `flv_` id, a foreign key into flow_versions so only an existing version can be
--   pinned). Moving the pin is an upsert of flow_version_id; a live flow keeps its stamped
--   version regardless.
--
-- Both tables are PROMOTABLE per-environment config the config-snapshot export carries (issue
-- #41, classification.rs): the whole non-secret artifact and the pin travel in a snapshot.
--
-- Migration safety obligation (see migrate.rs): the two NEW tenant-scoped tables each ENABLE and
-- FORCE row level security, add the (tenant, environment) isolation policy, add the nonempty
-- scope CHECK, and are registered in scripts/query-audit.sh. The flows foreign key is additive
-- (the column already exists, nullable, since 0079; a NULL row is unaffected). Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The append-only, per (tenant, environment, journey_id) versioned journey registry.
CREATE TABLE flow_versions (
    -- The flv_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The author-facing journey id this version belongs to (stable across the journey's versions).
    journey_id         text        NOT NULL,
    -- The per-scope, per-journey_id monotonic version number (1, 2, 3, ...).
    version            integer     NOT NULL,
    -- The canonical Journey artifact (a jsonb document), validated load-valid at write time
    -- (ironauth_journey::validate + compile). Never a secret (predicates reference pointers and
    -- names, never values).
    artifact           jsonb       NOT NULL,
    -- The actor ref that authored the version (operator-safe provenance).
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT flow_versions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '' AND journey_id <> ''),
    CONSTRAINT flow_versions_version_positive
        CHECK (version >= 1),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A version number is unique per (scope, journey_id): a second row claiming the same version for
-- a journey in a scope is refused, which is the append-only monotonic invariant.
CREATE UNIQUE INDEX flow_versions_scope_journey_version_unique
    ON flow_versions (tenant_id, environment_id, journey_id, version);
-- The engine lists a journey's versions and looks up the latest version for the next-version
-- computation on this ordered index.
CREATE INDEX flow_versions_scope_journey_idx
    ON flow_versions (tenant_id, environment_id, journey_id, version);

ALTER TABLE flow_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY flow_versions_tenant_isolation ON flow_versions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS journey authoring: create a version and read
-- versions. A version is immutable and never deleted (a change is a new version), so the control
-- plane holds SELECT and INSERT only, never UPDATE or DELETE. The DATA plane READS the pinned
-- version's artifact on the custom-flow creation and drive path, so it holds SELECT only.
GRANT SELECT, INSERT ON flow_versions TO ironauth_control;
GRANT SELECT ON flow_versions TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per (tenant, environment, journey_id) active-version pin.
CREATE TABLE flow_version_pins (
    -- The fvp_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The author-facing journey id this pin governs: the per-scope natural key. Unique per scope
    -- (one active version per journey).
    journey_id         text        NOT NULL,
    -- The pinned version's flv_ id: a foreign key into flow_versions, so only an existing version
    -- of this scope can be pinned. Moving the pin rewrites exactly this column.
    flow_version_id    text        NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT flow_version_pins_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '' AND journey_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (flow_version_id) REFERENCES flow_versions (id)
);

-- One active pin per (scope, journey_id): a repeat pin of the same journey upserts this row.
CREATE UNIQUE INDEX flow_version_pins_scope_journey_unique
    ON flow_version_pins (tenant_id, environment_id, journey_id);

ALTER TABLE flow_version_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_version_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY flow_version_pins_tenant_isolation ON flow_version_pins
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane OWNS the pin: create it and MOVE it (an upsert that rewrites flow_version_id).
-- Moving the pin is the only mutation, so the UPDATE grant is COLUMN-scoped to exactly
-- flow_version_id and updated_at, never a table-wide UPDATE (the #31 lesson): the control plane
-- can never rewrite the pin's journey_id or scope. The DATA plane READS the pin to resolve the
-- active version on custom-flow creation, so it holds SELECT only.
GRANT SELECT, INSERT ON flow_version_pins TO ironauth_control;
GRANT UPDATE (flow_version_id, updated_at) ON flow_version_pins TO ironauth_control;
GRANT SELECT ON flow_version_pins TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. Close the deferred foreign key from the flow row (issue #92, PR 4 -> PR 5).
--
-- flows.flow_version_id was added nullable in 0079 (NULL for every built-in flow). Now that the
-- target table exists, add the referential integrity: a stamped version must be a real version.
-- The column stays nullable, so a built-in flow with a NULL pin is unaffected.
ALTER TABLE flows
    ADD CONSTRAINT flows_flow_version_id_fkey
    FOREIGN KEY (flow_version_id) REFERENCES flow_versions (id);
