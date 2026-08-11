-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Dead-lettered log stream batches (issue #110).
--
-- A log stream is a CURSOR pipeline, not a queue, so dead-lettering means
-- something different here than it does for the webhook outbox and the
-- difference is the whole reason this table exists.
--
-- Without it, a batch the sink refuses forever is retried forever from the same
-- position, and the stream never advances past it. That is head-of-line
-- blocking: one poisoned batch stops every LATER event reaching the SIEM, and
-- the operator sees a stream that is failing rather than one that has stopped
-- exporting. Losing sight of a handful of events is bad; losing sight of
-- everything after them is worse.
--
-- So after a bounded run of failures the batch's RANGE is recorded here and the
-- cursor advances past it. The events themselves are not copied: they are still
-- in `audit_log`, and this row says which ones went undelivered and why. Replay
-- re-reads the range from the log rather than from a stored copy, so a replay
-- cannot deliver a stale rendering of an event, and this table stays small
-- however large the batch was.
--
-- The range is CLOSED on both ends and expressed in the same (occurred_at,
-- audit_id) order the cursor uses, so a replay reads exactly what the failed
-- pass read.

CREATE TABLE log_stream_dead_letters (
    -- The `lsd_` scoped identifier.
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The stream that could not deliver this range.
    stream_id           text        NOT NULL,
    -- The range, inclusive at both ends, in cursor order.
    from_occurred_at    timestamptz NOT NULL,
    from_audit_id       text        NOT NULL,
    to_occurred_at      timestamptz NOT NULL,
    to_audit_id         text        NOT NULL,
    -- How many events the failed batch carried, so an operator can see the size
    -- of the gap without re-reading the range.
    event_count         integer     NOT NULL,
    -- The failure that ended the retry run. Operator-safe, same discipline as
    -- log_streams.last_error: never a sink's response body.
    last_error          text        NOT NULL,
    dead_lettered_at    timestamptz NOT NULL,
    -- When a replay last delivered this range. NULL means still outstanding.
    replayed_at         timestamptz,
    CONSTRAINT log_stream_dead_letters_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT log_stream_dead_letters_count_positive CHECK (event_count > 0),
    -- A range that ends before it starts is not a range. Cheap to state, and it
    -- catches a from/to transposition at the call site, which would otherwise
    -- produce a replay that reads nothing and reports success.
    CONSTRAINT log_stream_dead_letters_range_ordered
        CHECK ((from_occurred_at, from_audit_id) <= (to_occurred_at, to_audit_id)),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The operator's question: what is outstanding for this stream.
CREATE INDEX log_stream_dead_letters_outstanding_idx
    ON log_stream_dead_letters (tenant_id, environment_id, stream_id, dead_lettered_at)
    WHERE replayed_at IS NULL;

ALTER TABLE log_stream_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_stream_dead_letters FORCE ROW LEVEL SECURITY;
CREATE POLICY log_stream_dead_letters_tenant_isolation ON log_stream_dead_letters
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The shipper records a dead letter and marks one replayed, so it needs INSERT
-- and a COLUMN-SCOPED update of the replay stamp only. Table-wide UPDATE would
-- let the data plane rewrite the range or the error, which is the record of what
-- went undelivered.
GRANT SELECT, INSERT ON log_stream_dead_letters TO ironauth_app;
GRANT UPDATE (replayed_at) ON log_stream_dead_letters TO ironauth_app;

-- The management plane lists them and drives a replay.
GRANT SELECT, INSERT, UPDATE, DELETE ON log_stream_dead_letters TO ironauth_control;
