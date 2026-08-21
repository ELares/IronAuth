-- HTTP flow targets (issue #112).
--
-- The escape hatch every incumbent ships, with the failure modes the issue names designed
-- out: Okta puts a 3-second HTTP call on the login path, and Ory configures hook bodies as
-- base64-encoded Jsonnet. So configuration here is plain JSON columns, and the timing column
-- below is what keeps a slow target off a latency-critical path.
--
-- # Why timing and failure policy are columns and not config JSON
--
-- Criterion 4 requires that parse-before-persist and fire-after-persist be "independently
-- selectable and observably different": a rejecting pre-persist target leaves NO row, a
-- post-persist target sees the COMMITTED row. That is a statement about transaction
-- boundaries, so the dispatcher has to branch on it before it opens a transaction at all.
-- A value buried in a JSON blob would be read after that decision was already made.
--
-- The same is true of the failure policy: criterion 6 says a sync target exceeding its timeout
-- triggers the policy "instead of hanging the flow", which means the policy must be known
-- before the call is made, not parsed out of config while the flow waits.

CREATE TABLE flow_targets (
    -- The `ftg_` scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,

    -- Operator-facing name, unique per environment among live targets.
    name              text        NOT NULL,

    -- The Zitadel Actions v2 taxonomy the issue adopts.
    target_class      text        NOT NULL,
    CONSTRAINT flow_targets_class_valid
        CHECK (target_class IN ('request', 'response', 'function', 'event')),

    -- SYNC targets can mutate or interrupt the flow and therefore block it; ASYNC targets are
    -- fire-and-forget through the webhook machinery and, per the issue, "cannot delay a flow".
    invocation        text        NOT NULL,
    CONSTRAINT flow_targets_invocation_valid
        CHECK (invocation IN ('sync', 'async')),

    -- Criterion 4's selector. `pre_persist` runs before the write is attempted so a rejection
    -- leaves no row; `post_persist` runs after commit so the target observes committed state.
    timing            text        NOT NULL,
    CONSTRAINT flow_targets_timing_valid
        CHECK (timing IN ('pre_persist', 'post_persist')),

    -- An ASYNC target cannot be pre-persist. Fire-and-forget means nothing waits for the
    -- answer, so "reject before the write" is not a thing it can do -- and a row claiming both
    -- would describe a dispatcher behaviour that does not exist. Refused here rather than
    -- silently coerced, because coercion would make an operator's stated intent quietly false.
    CONSTRAINT flow_targets_async_is_post_persist
        CHECK (invocation = 'sync' OR timing = 'post_persist'),

    -- Where it POSTs. Plain text, validated by the outbound policy at call time exactly as a
    -- log stream's endpoint is.
    endpoint          text        NOT NULL,

    -- Criterion 6: the bound on a SYNC call. NULL for async, which waits for nothing.
    timeout_ms        integer,
    CONSTRAINT flow_targets_sync_has_timeout
        CHECK (invocation = 'async' OR timeout_ms IS NOT NULL),
    CONSTRAINT flow_targets_timeout_positive
        CHECK (timeout_ms IS NULL OR timeout_ms > 0),

    -- What happens when a sync target times out or errors. `fail_open` continues the flow,
    -- `fail_closed` refuses it. Documented per target class by the issue; stored per target
    -- because the right answer differs -- a fraud check that fails open is not a fraud check,
    -- and a CRM sync that fails closed takes signup down when the CRM does.
    failure_policy    text        NOT NULL DEFAULT 'fail_closed',
    CONSTRAINT flow_targets_failure_policy_valid
        CHECK (failure_policy IN ('fail_open', 'fail_closed')),

    -- Plain JSON, NEVER code. The issue calls out Ory's base64-embedded Jsonnet as the
    -- ergonomic failure to avoid; transforms are REFERENCED from config, not embedded in it.
    config            jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- The per-target signing secret, by NAME. Never the value, for the reason 0137 gives:
    -- the surest way to guarantee this table never leaks a secret through a config read, an
    -- export or a snapshot is for it never to hold one.
    signing_secret_name text,

    -- Disabled targets stay configured and stop being dispatched, so an operator can stop a
    -- misbehaving integration without losing how it was set up.
    enabled           boolean     NOT NULL DEFAULT true,

    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    deleted_at        timestamptz,

    FOREIGN KEY (tenant_id, environment_id)
        REFERENCES environments (tenant_id, id) ON DELETE CASCADE
);

-- One LIVE target per name in an environment. Partial on deleted_at so a removed target frees
-- its name, matching every other soft-deleted resource here.
CREATE UNIQUE INDEX flow_targets_unique_name
    ON flow_targets (tenant_id, environment_id, name)
    WHERE deleted_at IS NULL;

-- Dispatch reads every ENABLED target of one class for a scope, which is what the index serves.
CREATE INDEX flow_targets_dispatch
    ON flow_targets (tenant_id, environment_id, target_class)
    WHERE deleted_at IS NULL AND enabled;

ALTER TABLE flow_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_targets FORCE ROW LEVEL SECURITY;

CREATE POLICY flow_targets_scope ON flow_targets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The app role DISPATCHES, so it reads. Registering a target is a management act: an app role
-- that could write one could point a flow's data at an endpoint it chose.
GRANT SELECT ON flow_targets TO ironauth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON flow_targets TO ironauth_control;
