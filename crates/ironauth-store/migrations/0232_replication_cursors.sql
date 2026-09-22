-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The replication cursor table (issue #155, EXPLORATORY).
--
-- A follower region's replication position: the highest home-region outbox `sequence`
-- shipped for each (tenant, environment). The follower OWNS this row; the home region
-- never writes it. The shipper reads it, copies the home outbox rows above it, and
-- advances it in the same transaction as the copy, so the position and the copied rows
-- can never disagree.
--
-- Bookkeeping table, like `_schema_migrations`: no RLS, because nothing here is
-- tenant-scoped user data and the row's tenant_id is a replication partition key, not an
-- access boundary. The data-plane role needs SELECT (the shipper runs on the follower
-- as the app role) and UPDATE (the cursor advance); the control role holds the same so
-- the management surface can read lag.
CREATE TABLE replication_cursors (
    tenant_id        text        NOT NULL,
    environment_id   text        NOT NULL,
    shipped_sequence bigint      NOT NULL,
    updated_at       timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, environment_id),
    CONSTRAINT replication_cursors_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT replication_cursors_sequence_nonnegative
        CHECK (shipped_sequence >= 0)
);

-- The #31 lesson: no table-wide UPDATE for the data-plane role. The cursor advance is
-- exactly two columns, so the grant is column-scoped; the control role (the management
-- surface's lag reader) gets the same two.
GRANT SELECT, UPDATE (shipped_sequence, updated_at) ON replication_cursors
    TO ironauth_app, ironauth_control;