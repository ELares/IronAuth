-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- SIEM log streams (issue #110).
--
-- A stream is a standing instruction to ship one or both audit streams to one
-- sink. The rows an operator configures here are configuration, not events: the
-- events themselves stay in `audit_log` and are read forward by a cursor kept on
-- this row, so a stream costs one row rather than one row per event shipped.
--
-- A cursor rather than a queue, deliberately. Enqueuing one message per audit
-- row per stream would double the write volume of the busiest table in the
-- system and multiply it by the number of configured streams, which is the
-- opposite of what a log pipeline should do. The cursor is (occurred_at,
-- audit_id), the same total order the chain sealer walks, so "everything before
-- this point has shipped" is expressible and resumable after a crash.
--
-- # What is NOT here
--
-- No organization column, and that absence is deliberate rather than pending.
-- Per-organization streams need an organization dimension on the AUDIT ROW,
-- which does not exist: `audit_log` records tenant, environment, actor, target
-- and action, and nothing says which organization an event belongs to. Adding a
-- nullable `organization_id` here without that would let an operator configure a
-- per-org stream that either silently ships nothing (filtering on a target
-- prefix that most actions do not have) or ships another org's events. A knob
-- that cannot be honoured is worse than an absent one, so the column arrives
-- with the audit dimension that makes it meaningful.
--
-- # Credentials
--
-- Never here. `credential_secret_name` NAMES an environment-scoped secret
-- (issue #45) and the sink resolves it at delivery time. Sink credentials must
-- not appear in a config read, an export, or a log, and the surest way to
-- guarantee that of this table is for it never to hold one.

CREATE TABLE log_streams (
    -- The `lgs_` scoped identifier; embeds its (tenant, environment).
    id                     text        PRIMARY KEY,
    tenant_id              text        NOT NULL,
    environment_id         text        NOT NULL,
    -- A human label for the operator listing streams. Never secret.
    description            text        NOT NULL DEFAULT '',
    -- Which audit stream(s) this ships: one of the two, or both.
    source                 text        NOT NULL,
    -- Where it ships to. The adapters behind this share one interface, so a peer
    -- (Sentinel, GCS, EventBridge) is a new value here and no core change.
    sink_type              text        NOT NULL,
    -- Sink shape: endpoint, region, bucket, index. NEVER a credential.
    sink_config            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- The environment-scoped secret holding this sink's credential, by NAME.
    credential_secret_name text,
    -- Ship only these action wire strings. NULL means every action in `source`.
    -- An EMPTY array is not the same as NULL: it ships nothing, which is a
    -- legitimate way to park a stream without deleting it.
    event_type_filter      text[],
    -- Whether the shipper picks this stream up.
    active                 boolean     NOT NULL DEFAULT true,
    -- The cursor: everything at or before this (occurred_at, audit_id) has
    -- shipped. NULL means nothing has shipped yet, so the stream starts at the
    -- oldest retained row.
    cursor_occurred_at     timestamptz,
    cursor_audit_id        text,
    -- Delivery health, for the status surface.
    last_success_at        timestamptz,
    last_error_at          timestamptz,
    -- The last failure, operator-safe: a status code and a reason, never a
    -- response body, which could carry back whatever the sink echoed.
    last_error             text,
    -- Consecutive failures with no success in between. A run rather than a rate:
    -- a busy sink that fails a fraction of the time is working, and only an
    -- unbroken run ending now says it has stopped answering.
    consecutive_failures   integer     NOT NULL DEFAULT 0,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT log_streams_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The two audit streams from 0133, plus `both`.
    CONSTRAINT log_streams_source_known
        CHECK (source IN ('admin_action', 'authentication', 'both')),
    CONSTRAINT log_streams_sink_type_known
        CHECK (sink_type IN ('http', 's3', 'datadog', 'splunk_hec')),
    -- The cursor is a PAIR: half of it is not a position. Either both columns
    -- are set or neither is.
    CONSTRAINT log_streams_cursor_whole
        CHECK (
            (cursor_occurred_at IS NULL AND cursor_audit_id IS NULL)
            OR (cursor_occurred_at IS NOT NULL AND cursor_audit_id IS NOT NULL)
        ),
    CONSTRAINT log_streams_failures_nonnegative
        CHECK (consecutive_failures >= 0),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The shipper asks one question: which active streams are in this scope.
CREATE INDEX log_streams_active_idx
    ON log_streams (tenant_id, environment_id, active);

-- Row-level security, ENABLED and FORCED, keyed on the same transaction-local
-- session variables every other scoped table uses.
ALTER TABLE log_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_streams FORCE ROW LEVEL SECURITY;
CREATE POLICY log_streams_tenant_isolation ON log_streams
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane SHIPS: it reads the configuration and advances the cursor and
-- the health columns, and it may write NOTHING ELSE. The UPDATE is COLUMN
-- SCOPED, which is the #31 lesson and is load-bearing here rather than tidy.
--
-- A table-wide UPDATE would let a compromised data-plane credential rewrite
-- `sink_config`, which is the DESTINATION: the export would keep running, keep
-- reporting healthy, and deliver every audit event in the environment to an
-- endpoint the operator never configured. Nothing about that failure looks like
-- a failure. It would also let the data plane rewrite `event_type_filter` to
-- silently narrow what an operator believes is being exported.
--
-- So the grant names exactly the six columns a shipper advances, and the
-- destination, the filter, the source selection and the active switch stay
-- writable only by the management plane.
GRANT SELECT ON log_streams TO ironauth_app;
GRANT UPDATE (
    cursor_occurred_at,
    cursor_audit_id,
    last_success_at,
    last_error_at,
    last_error,
    consecutive_failures
) ON log_streams TO ironauth_app;

-- The management plane configures streams end to end.
GRANT SELECT, INSERT, UPDATE, DELETE ON log_streams TO ironauth_control;
