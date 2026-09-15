-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-tenant quota limits, settable at runtime (issue #150 criterion 4).
--
-- Criterion 4 asks that "limits and tier assignments change at runtime per tenant via the
-- management API without restart". Until now quota lived only in `QuotaConfig`, which is
-- read from the config file at boot, so changing one tenant's limit meant editing a file and
-- restarting every node. That is not a runtime change, and on a multi-tenant deployment it
-- is a restart of everyone's service to adjust one customer.
--
-- This table is the override layer. A scope with no row here uses the configured default,
-- which is what makes the table safe to add: an empty table changes nothing about how the
-- deployment behaves today.
--
-- WHY A ROW PER DIMENSION rather than a row per scope with columns per dimension. The
-- dimensions are an open set (`QuotaDimension` has grown twice), and a column per dimension
-- makes each addition a migration against a table the data plane reads on the request path.
-- A row per dimension makes it an insert.

CREATE TABLE tenant_quota_limits (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- Which quota dimension this overrides, as `QuotaDimension::as_str` renders it. TEXT
    -- rather than an enum type for the reason above: a new dimension must not need a
    -- migration, and an unknown value here is ignored by a reader that does not know it,
    -- which is the safe direction for a rolling upgrade.
    dimension      text        NOT NULL,
    -- The sustained rate and the burst, in the same units `Limit` uses. Non-negative and
    -- finite, checked here rather than only in Rust: this table is writable by the control
    -- plane, and a NaN or a negative rate reaching the limiter would make it stop limiting.
    refill_per_sec double precision NOT NULL,
    burst          double precision NOT NULL,
    -- For an operator answering "when did this change", and for the invalidation SLO: a
    -- reader compares this against what it has cached.
    updated_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, environment_id, dimension),

    -- NaN IS COMPARED EXPLICITLY, because Postgres float semantics are NOT IEEE-754 here
    -- and the obvious guards both pass it. Postgres defines NaN = NaN as TRUE and NaN as
    -- GREATER than every other value, so that floats can be indexed and sorted: the usual
    -- `value = value` NaN idiom returns true, and `value >= 0` returns true as well. A test
    -- caught this, which is the only reason it is not in the shipped constraint.
    CONSTRAINT tenant_quota_limits_refill_sane
        CHECK (refill_per_sec >= 0
               AND refill_per_sec <> 'NaN'::double precision
               AND refill_per_sec <> 'Infinity'::double precision),
    CONSTRAINT tenant_quota_limits_burst_sane
        CHECK (burst >= 0
               AND burst <> 'NaN'::double precision
               AND burst <> 'Infinity'::double precision)
);

ALTER TABLE tenant_quota_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_quota_limits FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_quota_limits_scope ON tenant_quota_limits
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT ONLY for the data plane. The request path READS a limit and never writes one: the
-- writer is the management API, which runs as the control-plane role. A table-wide UPDATE
-- here would let a compromised data-plane path raise its own tenant's limit, which is the
-- one write that defeats the feature entirely (the #31 lesson, enforced by
-- `the_data_plane_holds_no_table_wide_update_on_any_table`).
GRANT SELECT ON tenant_quota_limits TO ironauth_app;
