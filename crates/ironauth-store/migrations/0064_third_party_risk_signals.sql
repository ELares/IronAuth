-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Third-party risk-signal ingestion store: the risk_signals table (issue #82, PR 1).
--
-- An external fraud/risk source (a device-reputation vendor, a bot-detection service,
-- a partner IdP emitting CAEP events) can deliver a SIGNAL about a subject as a SIGNED
-- Security Event Token (RFC 8417 SET, a JWS). The signal is authenticated by its
-- signature against a per-source registered public key (never a shared bearer secret)
-- and ingested as one row here. The #79 risk engine later reads a subject's FRESH
-- signals and folds each in as ONE WEIGHTED contribution to its deterministic
-- LOW/MED/HIGH score. A signal is a POLICY INPUT, never a verdict: nothing here carries
-- a final action, so an ingested row can only ever become one SignalOutcome the engine
-- combines, and a source can hard-deny only when the operator opted that source in.
--
--   risk_signals: one row per ingested (source, source_jti) delivery.
--     - a scope-embedded `rsg_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - source: the signal source identity, which is the SET `iss` the ingestion
--       verified the signature under. It MUST match an enabled per-source entry in the
--       env RiskConfig for the engine to read the row (an unreferenced source is inert);
--     - signal_type: a FREE-TEXT, URI-capable event-type token, so a CAEP event-type
--       URI (for example the risk-level-change event) is stored verbatim with no schema
--       change as new event types appear;
--     - subject_format: the RFC 9493 Subject Identifier format the source asserted the
--       subject under, pinned to a closed set;
--     - subject_bidx: the BLIND INDEX (a per-tenant keyed HMAC) of the raw external
--       subject the source asserted. The raw external subject can be an email or a phone
--       number (PII), so it is NEVER stored in a queryable plaintext column: only its
--       keyed blind index lands, exactly like `users.identifier_bidx`, so a database dump
--       reveals no external subject and no cross-tenant linkage;
--     - subject: the RESOLVED local `usr_` id the raw external subject mapped to (via the
--       user identifier blind index), or NULL when it resolves to no local account. The
--       engine keys its fresh-signal read on this column; a NULL-subject row is inert;
--     - payload: the tagged signal body `{kind:"verdict"|"score", verdict?, score?,
--       attrs?}`. The per-source RiskConfig declares how a verdict string or a numeric
--       score maps to a RiskLevel contribution, so the payload carries only the source's
--       raw assertion, never a resolved action;
--     - event_timestamp: the source's event instant (the CAEP `event_timestamp`), the
--       FRESHNESS input. The engine treats a signal older than the per-source configured
--       max age as STALE and drops it, so a stale row never counts as a policy input;
--     - source_jti: the SET `jti`, the single-delivery dedup key. Re-delivering the same
--       (source, source_jti) is an idempotent no-op (the UNIQUE below), so a source can
--       retry a delivery without double-counting;
--     - received_at: the ingestion instant (the database clock DEFAULT).
--
--     Runtime data (issue #41): an ingested risk signal is dynamic per-environment risk
--     state (like a risk_decision or a login-geo observation), NEVER promotable config,
--     so it STRUCTURALLY never enters a config snapshot (only Promotable types are
--     exported) and carries no first-class ResourceType variant. There is no control-plane
--     grant: a signal is runtime risk state, never part of an account export.
--
-- SSF/CAEP forward-compatibility (issue #82): this schema is a SUPERSET of a CAEP SET, so
-- an M14 RISC/CAEP receiver becomes a SECOND row-writer with NO schema change. The SET
-- `iss` maps to `source`, the `events` map key (an event-type URI) to `signal_type`, the
-- RFC 9493 `sub_id` `{format, ...}` to `subject_format` + `subject_bidx` (+ the resolved
-- `subject`), the event `event_timestamp` to `event_timestamp`, the event-specific claims
-- to the `payload` jsonb, and the SET `jti` to `source_jti`. Because `signal_type` is free
-- text and `payload` is jsonb, a new CAEP event type needs no migration.
--
-- The UNIQUE (tenant, environment, source, source_jti) constraint is the STRUCTURAL
-- single-delivery invariant: a given source's SET is ingested at most once per scope, so a
-- guarded ON CONFLICT DO NOTHING insert either wins (first delivery) or is a no-op (a
-- retry / replay), never an error the caller must interpret.
--
-- Migration safety obligation (see migrate.rs): every NEW tenant-scoped table ENABLES and
-- FORCES row-level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The third-party risk-signal ingestion store (issue #82, PR 1).
CREATE TABLE risk_signals (
    -- The rsg_ scoped identifier; embeds its (tenant, environment).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The signal source identity: the SET `iss` the signature verified under. Must match
    -- an enabled RiskConfig source for the engine to read this row.
    source         text        NOT NULL,
    -- A free-text, URI-capable event-type token (a CAEP event-type URI fits verbatim).
    signal_type    text        NOT NULL,
    -- The RFC 9493 Subject Identifier format the source asserted, a closed set.
    subject_format text        NOT NULL,
    -- The blind index (a per-tenant keyed HMAC) of the raw external subject. The raw
    -- external subject can be PII (an email/phone), so it is never a plaintext column.
    subject_bidx   bytea       NOT NULL,
    -- The resolved local `usr_` id the external subject mapped to, or NULL when it maps to
    -- no local account. The engine keys its fresh-signal read on this column.
    subject        text,
    -- The tagged signal body {kind:"verdict"|"score", ...}; the per-source config maps it
    -- to a RiskLevel contribution. Carries no resolved action.
    payload        jsonb       NOT NULL,
    -- The source's event instant (CAEP event_timestamp): the freshness input the engine
    -- compares against the per-source max age to drop a stale signal.
    event_timestamp timestamptz NOT NULL,
    -- The SET `jti`: the single-delivery dedup key.
    source_jti     text        NOT NULL,
    received_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT risk_signals_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed RFC 9493 subject-format set: an unknown format can never be written.
    CONSTRAINT risk_signals_subject_format_known
        CHECK (subject_format IN ('account', 'email', 'phone_number', 'iss_sub', 'opaque')),
    -- The STRUCTURAL single-delivery invariant: a source's SET is ingested at most once per
    -- scope, so a re-delivery is an idempotent no-op rather than a duplicate row.
    CONSTRAINT risk_signals_delivery_uniq
        UNIQUE (tenant_id, environment_id, source, source_jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX risk_signals_scope_idx
    ON risk_signals (tenant_id, environment_id);
-- The engine reads a subject's fresh signals newest first (the eval read).
CREATE INDEX risk_signals_subject_idx
    ON risk_signals (tenant_id, environment_id, subject, event_timestamp);

ALTER TABLE risk_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_signals FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_signals_tenant_isolation ON risk_signals
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane INGESTS a verified signal (INSERT) and the engine READS a subject's fresh
-- signals (SELECT). A signal is immutable once written (no UPDATE, no DELETE: the
-- append-only posture, a retention sweep runs as the owner role). There is NO control-plane
-- grant: a signal is runtime risk state, structurally never part of an account export.
GRANT SELECT, INSERT ON risk_signals TO ironauth_app;
