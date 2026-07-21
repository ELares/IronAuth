-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Policy decision traces and the token size event sink for the M9 flow inspector (issue #91).
--
-- The admin flow inspector surfaces WHY a policy decision came out the way it did, kept off
-- the request path. This migration adds two out of band, append only, retention pruned sinks,
-- both modeled on the risk_decisions record (migration 0054) and the client_auth_diagnostics
-- sink (migration 0013): tenant and environment scoped, forced row level security, an on
-- insert prune, and NEVER a first class resource type (so neither travels in a config
-- snapshot, exactly like risk_decisions).
--
-- 1. policy_decision_traces records the three traced policy decision points (step up, risk,
--    and claim mapping) as STRUCTURALLY REDACTED safe field traces. decision_inputs is a
--    jsonb projection of bounded, non secret fields only (the acr floor and achieved acr, the
--    auth age, the risk signal NAMES and levels, the connector slug and the mapped trait
--    count); it can NEVER hold a claim value, a token, or a secret, because the recorder builds
--    it from typed safe fields (see PolicyDecisionInputs), not from raw claims. outcome is a
--    closed verdict set and reason is a bounded, non secret hint. subject, when present, is the
--    internal usr_ handle the decision was for (a blind reference, never raw PII), exactly as
--    risk_decisions.subject carries it.
--
-- 2. token_size_events records a mint whose serialized ID token EXCEEDED a bloat threshold: an
--    operational warning that the token grew large (too many claims), so the operator can see
--    it in the warnings read. It carries only the token TYPE, the byte SIZE, and the claim
--    COUNT (bounded integers), plus the non secret client id; it can NEVER hold the token
--    itself. This is the one materialized warning (the rest are computed live on read).
--
-- Retention (bounded growth). Both sinks are written on hot paths (an authorization, a login,
-- a token mint), so without retention they would grow one row per request. expires_at
-- (occurred_at + the diagnostics retention window, from DiagnosticsConfig) bounds each table:
-- the recorder prunes expired rows before each insert, exactly like the jti cache and the
-- client_auth_diagnostics sink. This is a growth bound only, NOT rate limiting.

-- ---------------------------------------------------------------------------
-- The policy decision trace sink.
CREATE TABLE policy_decision_traces (
    -- A random per row identifier (from the application entropy seam), so a row is
    -- addressable without leaking an ordering or a count.
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- Which policy decision this trace records (the closed set the M9 inspector traces).
    policy          text        NOT NULL,
    -- The internal usr_ handle the decision was for, when the decision point has one (a blind
    -- reference, never raw PII); NULL for a decision point with no local subject yet (a claim
    -- mapping evaluation runs BEFORE provisioning).
    subject         text,
    -- The bounded verdict the decision reached.
    outcome         text        NOT NULL,
    -- A bounded, non secret reason hint (for example which step up dimension was unmet, the
    -- risk action verb, or the claim mapping failure kind); NULL when the verdict is enough.
    reason          text,
    -- The REDACTED, allowlisted safe field projection of the decision inputs, built by the
    -- recorder from typed safe fields (see PolicyDecisionInputs). It carries NO claim value,
    -- token, or secret: those are unrepresentable here, not scrubbed after the fact.
    decision_inputs jsonb       NOT NULL,
    -- When the decision happened, from the application clock seam (never the database clock),
    -- so it is deterministic under a manual clock in tests.
    occurred_at     timestamptz NOT NULL,
    -- When this row may be pruned (occurred_at + the retention window), from the application
    -- clock seam, so the on insert prune is deterministic under a manual clock.
    expires_at      timestamptz NOT NULL,
    -- When the row was persisted, from the database clock. Operational metadata only.
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT policy_decision_traces_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed policy set: an unknown decision point can never be written.
    CONSTRAINT policy_decision_traces_policy_known
        CHECK (policy IN ('step_up', 'risk', 'claim_mapping')),
    -- The closed verdict set: an unknown outcome can never be written.
    CONSTRAINT policy_decision_traces_outcome_known
        CHECK (outcome IN ('satisfied', 'step_up_required', 'deny')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX policy_decision_traces_scope_idx
    ON policy_decision_traces (tenant_id, environment_id, occurred_at);

-- The on insert prune scans expired rows within scope by expiry.
CREATE INDEX policy_decision_traces_expiry_idx
    ON policy_decision_traces (tenant_id, environment_id, expires_at);

ALTER TABLE policy_decision_traces ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_decision_traces FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_decision_traces_tenant_isolation ON policy_decision_traces
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane records a trace (INSERT), prunes expired rows on insert (DELETE), and reads
-- it back for tests (SELECT). The control plane reads traces for the M9 admin flow inspector
-- (SELECT only), exactly as it reads risk_decisions and the client_auth_diagnostics sink; it
-- never writes or prunes them.
GRANT SELECT, INSERT, DELETE ON policy_decision_traces TO ironauth_app;
GRANT SELECT ON policy_decision_traces TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The token size event sink (the one materialized operational warning).
CREATE TABLE token_size_events (
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The token TYPE the size event is about (the closed set).
    token_type      text        NOT NULL,
    -- The serialized token byte size that tripped the bloat threshold. A bounded integer,
    -- never the token itself.
    byte_size       bigint      NOT NULL,
    -- The token's claim count, when known (an integer, never a claim value).
    claim_count     bigint,
    -- The client the token was minted for (a non secret identifier).
    client_id       text        NOT NULL,
    occurred_at     timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT token_size_events_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT token_size_events_type_known
        CHECK (token_type IN ('id_token', 'access_token')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX token_size_events_scope_idx
    ON token_size_events (tenant_id, environment_id, occurred_at);

CREATE INDEX token_size_events_expiry_idx
    ON token_size_events (tenant_id, environment_id, expires_at);

ALTER TABLE token_size_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_size_events FORCE ROW LEVEL SECURITY;
CREATE POLICY token_size_events_tenant_isolation ON token_size_events
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT, INSERT, DELETE ON token_size_events TO ironauth_app;
GRANT SELECT ON token_size_events TO ironauth_control;
