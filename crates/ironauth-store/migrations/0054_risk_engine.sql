-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Minimal risk engine state (issue #79).
--
-- The design bet is LEGIBILITY over ML: a small set of explainable signals feed a
-- three-level score (LOW/MED/HIGH) and a three-verb action vocabulary
-- (block/challenge/notify), and EVERY decision is traceable and auditable. This
-- migration lands the durable state the engine reads and writes on the RELATIONAL
-- store (IronCache is an OPTIONAL accelerator only, per the
-- no-mandatory-first-party-infrastructure covenant): three new tenant-scoped tables
-- with forced row-level security.
--
--   risk_login_geo: one row per subject, the LAST-SEEN coarse location and instant a
--     login was observed from. The impossible-travel signal reads it to compute
--     geo-velocity between consecutive logins (via a PLUGGABLE GeoIP provider seam;
--     the default null provider yields no coordinates, so the signal is inert until a
--     provider is wired). The observed IP, coarse location, and User-Agent are
--     end-user device metadata (PII), each SEALED under the scope's envelope DEK
--     (issue #48); pii_dek_version records the DEK they were sealed under. There is
--     exactly one row per (tenant, environment, subject): a fresh login UPSERTs it, so
--     the "history" the velocity check reads is the immediately preceding login.
--
--   risk_decisions: one row per scored login, the persisted DECISION RECORD. It holds
--     the LOW/MED/HIGH score, the action taken (allow/block/challenge/notify), and the
--     enumerated contributing signals with their typed values in a jsonb document, so
--     a sampled decision is fully RECONSTRUCTABLE. The record carries NO plaintext PII:
--     only derived signal names, booleans, enums, and counts (never the raw IP, the
--     raw location, or the User-Agent). The audit log (Action::RiskDecisionRecord)
--     carries the score, the action, AND a compact enumerated signal summary (the signal
--     kinds plus levels, PII-free), so the decision is reconstructable from the audit
--     trail alone even if this row is pruned (both tables are append-only).
--
--   risk_disavowal_tokens: one row per "this wasn't me" token planted in a new-device
--     notification. Only the SHA-256 DIGEST of the high-entropy single-use token is
--     stored (server-side state, never the self-contained secret), so a database dump
--     reveals no usable link. The row names the sessions the disavowal revokes and is
--     single-use (consumed_at, set exactly once). A CONSUMED token is itself the
--     durable "credentials flagged for review" marker for the subject.
--
-- Migration safety obligation (see migrate.rs): every NEW tenant-scoped table ENABLES
-- and FORCES row-level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per-subject last-seen login geo (issue #79), read by the impossible-travel
-- signal. id is an `rgl_` scoped identifier. subject is the `usr_` id the observation
-- belongs to; every read and write filters on it. The observed IP, coarse location,
-- and User-Agent are sealed under the scope's active DEK (issue #48); pii_dek_version
-- records the DEK version. observed_at is the login instant (via env.clock()), read as
-- the "from" time of the geo-velocity computation.
CREATE TABLE risk_login_geo (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The end-user subject (a `usr_` id) this last-seen observation belongs to.
    subject             text        NOT NULL,
    -- The observed peer IP at login, sealed under the scope's DEK (issue #48).
    -- End-user device metadata (PII): never a plaintext column.
    ip_sealed           bytea       NOT NULL,
    -- The resolved coarse location (a small JSON document of latitude, longitude, and
    -- optional ASN) at login, sealed under the scope's DEK (issue #48). The velocity
    -- check opens it to compute the great-circle distance to the current login. Never
    -- a plaintext column.
    geo_sealed          bytea       NOT NULL,
    -- The observed User-Agent at login, sealed under the scope's DEK (issue #48).
    -- Never a plaintext column.
    user_agent_sealed   bytea       NOT NULL,
    -- The DEK version the three sealed columns were sealed under.
    pii_dek_version     integer     NOT NULL,
    -- The login instant this observation was recorded at (the "from" time of the
    -- geo-velocity computation), via env.clock().
    observed_at         timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT risk_login_geo_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- Exactly one last-seen row per subject: a fresh login UPSERTs it.
CREATE UNIQUE INDEX risk_login_geo_subject_idx
    ON risk_login_geo (tenant_id, environment_id, subject);

ALTER TABLE risk_login_geo ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_login_geo FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_login_geo_tenant_isolation ON risk_login_geo
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane records a login geo (INSERT), reads the previous one (SELECT), and
-- refreshes it on a subsequent login (a COLUMN-scoped UPDATE). COLUMN-scoped UPDATE
-- only (the #31 least-privilege lesson).
GRANT SELECT, INSERT ON risk_login_geo TO ironauth_app;
GRANT UPDATE (ip_sealed, geo_sealed, user_agent_sealed, pii_dek_version, observed_at, updated_at)
    ON risk_login_geo TO ironauth_app;
-- The exit-export surface reads the sealed observation for the account export (issue
-- #58 covenant): SELECT and INSERT, no more (least privilege, mirroring 0053).
GRANT SELECT, INSERT ON risk_login_geo TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The persisted risk decision record (issue #79). id is an `rsk_` scoped identifier.
-- subject is the `usr_` id the login was for. score is the LOW/MED/HIGH level; action
-- is the dispatched verb. signals is a jsonb document enumerating each contributing
-- signal and its typed value (booleans, enums, counts) so the decision is fully
-- reconstructable; it carries NO plaintext PII.
CREATE TABLE risk_decisions (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The end-user subject (a `usr_` id) this login was scored for.
    subject             text        NOT NULL,
    -- The request correlation id the decision belongs to (audit lineage), if any.
    correlation_id      text,
    -- The LOW/MED/HIGH score (a closed set).
    score               text        NOT NULL,
    -- The dispatched action verb (a closed set: allow/block/challenge/notify).
    action              text        NOT NULL,
    -- The enumerated contributing signals and their typed values (no plaintext PII),
    -- so a sampled decision is fully reconstructable from this row.
    signals             jsonb       NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT risk_decisions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed score set: an unknown level can never be written.
    CONSTRAINT risk_decisions_score_known
        CHECK (score IN ('low', 'med', 'high')),
    -- The closed action set: exactly the three-verb vocabulary plus the allow default.
    CONSTRAINT risk_decisions_action_known
        CHECK (action IN ('allow', 'block', 'challenge', 'notify')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX risk_decisions_scope_idx
    ON risk_decisions (tenant_id, environment_id);
-- The account view and any audit sampling read a subject's decisions newest first.
CREATE INDEX risk_decisions_subject_idx
    ON risk_decisions (tenant_id, environment_id, subject, created_at, id);

ALTER TABLE risk_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_decisions_tenant_isolation ON risk_decisions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane records a decision (INSERT) and reads it back (SELECT); a decision is
-- immutable once written (no UPDATE, no DELETE: the append-only audit posture).
GRANT SELECT, INSERT ON risk_decisions TO ironauth_app;
-- The control plane reads decisions for the account export and audit sampling.
GRANT SELECT ON risk_decisions TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The "this wasn't me" disavowal token (issue #79). id is a `dis_` scoped identifier
-- that doubles as the routing handle in the token wire form `ira_dis_<id>~<secret>`.
-- token_digest is the SHA-256 digest of the high-entropy secret (server-side state,
-- never the self-contained secret). session_ids names the sessions the disavowal
-- revokes. consumed_at is the single-use latch: a CONSUMED token is the durable
-- "credentials flagged for review" marker for the subject.
CREATE TABLE risk_disavowal_tokens (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The end-user subject (a `usr_` id) this disavowal is for.
    subject             text        NOT NULL,
    -- The SHA-256 digest of the token's high-entropy secret: server-side state, never
    -- the self-contained secret. A presented token is validated by hashing its secret
    -- to this digest AND checking the row is live (not consumed, not expired).
    token_digest        bytea       NOT NULL,
    -- The `rsk_` risk decision this disavowal descends from (audit lineage), if any.
    decision_id         text,
    -- The `ses_` sessions the disavowal revokes (the sessions in question).
    session_ids         text[]      NOT NULL DEFAULT '{}',
    -- The single-use latch: set exactly once when the user follows the link. A CONSUMED
    -- token is the durable "credentials flagged for review" marker.
    consumed_at         timestamptz,
    -- Past this instant the token no longer disavows (enforced authoritatively).
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT risk_disavowal_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX risk_disavowal_tokens_subject_idx
    ON risk_disavowal_tokens (tenant_id, environment_id, subject, created_at, id);
-- A presented token resolves the ONE candidate row by its secret digest.
CREATE UNIQUE INDEX risk_disavowal_tokens_digest_idx
    ON risk_disavowal_tokens (tenant_id, environment_id, token_digest);

ALTER TABLE risk_disavowal_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_disavowal_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_disavowal_tokens_tenant_isolation ON risk_disavowal_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane mints a disavowal token (INSERT), resolves a presented one (SELECT),
-- and consumes it single-use (a COLUMN-scoped UPDATE to consumed_at). COLUMN-scoped
-- UPDATE only (the #31 least-privilege lesson).
GRANT SELECT, INSERT ON risk_disavowal_tokens TO ironauth_app;
GRANT UPDATE (consumed_at) ON risk_disavowal_tokens TO ironauth_app;
-- The control plane reads the review markers for the account export.
GRANT SELECT ON risk_disavowal_tokens TO ironauth_control;
