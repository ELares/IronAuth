-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Advanced recovery modes: the recovery-method seam on the account-recovery flow, plus
-- the three mode state tables (issue #82, PR 3).
--
-- The account-recovery subsystem (issue #81) is a first-class state machine with three
-- pillars an advanced mode must NEVER weaken: DELAY as a security feature (a
-- security-reducing recovery is HELD for the configured window before it can complete),
-- NOTIFICATION on every registered channel, and the DOWNGRADE INVARIANT (recovery can
-- never silently remove a factor STRONGER than the one used to recover). The recovery flow
-- had NO pluggable method today: it was always the standard self-service email-OTP path,
-- and RecoveryFlowRepo::complete had no live caller. This migration adds the METHOD
-- dimension and the four state tables the three advanced modes plug into. Every mode
-- completes THROUGH the existing completion gate (the hold_until delay guard on complete()
-- and the factor_change_decision downgrade invariant): a mode can only ADD a precondition,
-- never bypass the delay or the downgrade block.
--
--   recovery_flows.method: WHICH recovery method a flow uses, pinned to a closed set. The
--     default 'standard' back-fills every existing row to the unchanged issue #81 path, so
--     the ALTER changes no existing flow's behavior. The data plane SETS method at INSERT
--     (the table-wide INSERT grant covers the new column); it is never mutated afterward,
--     so no new column-scoped UPDATE grant is added.
--
--   recovery_approvals (admin-approved mode): one pending approval per admin-approved
--     recovery flow. The control plane (an admin) decides it; the deciding admin actor is
--     stamped on the row (audit-grade) and the approval, once 'approved', is the method
--     precondition the completion gate ANDs with the delay/downgrade rules. A quarantined
--     or recovering END USER holds no management principal, so it can never reach the
--     approve/reject path: self-approval is structurally impossible.
--
--   recovery_trusted_contacts (trusted-contact enrollment): the contacts a user designates
--     to confirm a recovery out of band. The contact address (an email/phone) is SEALED
--     under the scope DEK (issue #48), exactly like recovery_flows.recipient_sealed, so a
--     database dump reveals no contact PII.
--
--   recovery_contact_confirmations (trusted-contact per-flow confirmations): one row per
--     (flow, contact) confirmation. Only the SHA-256 digest of the single-use confirmation
--     token is stored (never the token), mirroring recovery_flows.cancel_token_digest. The
--     UNIQUE (tenant, env, flow_id, contact_id) is the no-double-count invariant: one
--     contact can confirm a flow at most once, so a single contact can never reach a
--     threshold of two by confirming twice.
--
--   recovery_idv_sessions (IDV-gated mode): the external-verification session for an
--     idv-method recovery. The redirect_state_digest is a single-use nonce BOUND to the
--     flow (the UNIQUE (tenant, env, flow_id, redirect_state_digest) closes cross-case
--     replay), consumed_at is the single-use latch (mirroring fedcm_assertion_nonces 0063),
--     and verdict records the callback's asserted pass/fail. A callback completes the
--     recovery ONLY when its signature verifies against the provider's registered key, its
--     nonce matches this session (case binding), the row is not yet consumed (single use),
--     and the verdict is a pass.
--
--     All four tables are Runtime data (issue #41): dynamic per-environment recovery state,
--     like recovery_flows itself, NEVER promotable config, so they STRUCTURALLY never enter
--     a config snapshot (only Promotable types are exported) and carry no ResourceType
--     variant. There is no control-plane SELECT grant beyond recovery_approvals' review
--     columns: recovery state is never part of an account export.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table ENABLES and
-- FORCES row-level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. The recovery_flows
-- ALTER is additive with a DEFAULT, so it back-fills every existing row to 'standard'.
-- Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The recovery-method seam on the existing flow (issue #82, PR 3). Additive with a DEFAULT,
-- so every existing recovery_flows row back-fills to the unchanged 'standard' issue #81
-- path. The data plane sets method at INSERT (the table-wide INSERT grant covers it); it is
-- never mutated afterward, so no column-scoped UPDATE grant is needed.
ALTER TABLE recovery_flows
    ADD COLUMN method text NOT NULL DEFAULT 'standard';
ALTER TABLE recovery_flows
    ADD CONSTRAINT recovery_flows_method_known
        CHECK (method IN ('standard', 'admin_approved', 'trusted_contact', 'idv'));

-- Admin-approved recovery completes on the CONTROL plane: after an admin approves the case,
-- the management handler completes the recovery flow THROUGH the #81 completion gate (the
-- `complete()` UPDATE, whose `hold_until <= now` guard enforces the delay). The control role
-- needs a COLUMN-SCOPED UPDATE over exactly the completion columns to do that; it does NOT get
-- the cancel/hold columns (only the data plane initiates and cancels). Additive grant, so this
-- stays an EXPAND.
GRANT UPDATE (state, completed_at) ON recovery_flows TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Admin-approved recovery: the pending-approval queue row (issue #82, PR 3).
CREATE TABLE recovery_approvals (
    -- The rap_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The recovery flow (rcv_) this approval decides (the anti-IDOR / join key).
    flow_id           text        NOT NULL,
    -- The recovering usr_ subject the case is about (the anti-IDOR filter the admin read
    -- and the approve/reject writes key on).
    subject           text        NOT NULL,
    -- The review position, a closed set. 'pending' is the OPEN state; 'approved' is the
    -- method precondition the completion gate ANDs with the delay/downgrade rules;
    -- 'rejected' is the terminal refusal.
    state             text        NOT NULL DEFAULT 'pending',
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- The deciding admin actor, stamped once a review action runs (audit-grade inline copy;
    -- the audit_log carries the same attribution).
    reviewed_by_kind  text,
    reviewed_by_id    text,
    reviewed_at       timestamptz,
    -- An OPTIONAL operator note recorded with a review decision.
    note              text,
    CONSTRAINT recovery_approvals_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT recovery_approvals_state_known
        CHECK (state IN ('pending', 'approved', 'rejected')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_approvals_scope_idx
    ON recovery_approvals (tenant_id, environment_id);
-- The admin review-queue keyset read (open cases, oldest first, over (created_at, id)).
CREATE INDEX recovery_approvals_queue_idx
    ON recovery_approvals (tenant_id, environment_id, state, created_at, id);
-- One approval row per flow: an admin-approved recovery has at most one open decision.
CREATE UNIQUE INDEX recovery_approvals_flow_uniq
    ON recovery_approvals (tenant_id, environment_id, flow_id);

ALTER TABLE recovery_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_approvals_tenant_isolation ON recovery_approvals
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane OPENS an approval (INSERT) when it lands an admin-approved recovery, and
-- reads it back (SELECT). The control plane (the admin review queue) READS the queue
-- (SELECT) and OWNS the verdict: a COLUMN-SCOPED UPDATE over exactly the review columns, so
-- the data plane can never move a case forward and the control plane can never rewrite the
-- case's identity (its flow_id or subject). This mirrors the #31 / PR 2 split.
GRANT SELECT, INSERT ON recovery_approvals TO ironauth_app;
GRANT SELECT ON recovery_approvals TO ironauth_control;
GRANT UPDATE (state, reviewed_by_kind, reviewed_by_id, reviewed_at, note)
    ON recovery_approvals TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Trusted-contact recovery: the user-designated contacts (issue #82, PR 3).
CREATE TABLE recovery_trusted_contacts (
    -- The rtc_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The usr_ subject who designated this contact (the anti-IDOR filter).
    subject           text        NOT NULL,
    -- The contact address (an email/phone), SEALED under the scope DEK (issue #48), so a
    -- database dump reveals no contact PII. Mirrors recovery_flows.recipient_sealed.
    contact_sealed    bytea       NOT NULL,
    -- The DEK version the contact was sealed under, for unseal on notify.
    pii_dek_version   integer     NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recovery_trusted_contacts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_trusted_contacts_scope_idx
    ON recovery_trusted_contacts (tenant_id, environment_id);
-- The per-subject enrollment read (list a subject's designated contacts).
CREATE INDEX recovery_trusted_contacts_subject_idx
    ON recovery_trusted_contacts (tenant_id, environment_id, subject, created_at, id);

ALTER TABLE recovery_trusted_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_trusted_contacts FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_trusted_contacts_tenant_isolation ON recovery_trusted_contacts
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane enrolls (INSERT) and lists (SELECT) a subject's contacts. Runtime recovery
-- state: no control-plane grant (never part of an account export).
GRANT SELECT, INSERT ON recovery_trusted_contacts TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Trusted-contact recovery: the per-flow out-of-band confirmations (issue #82, PR 3).
CREATE TABLE recovery_contact_confirmations (
    -- The rcc_ scoped identifier; embeds its (tenant, environment).
    id                   text        PRIMARY KEY,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,
    -- The recovery flow (rcv_) this confirmation is for (the anti-cross-case filter).
    flow_id              text        NOT NULL,
    -- The designated contact (rtc_) that must confirm.
    contact_id           text        NOT NULL,
    -- The SHA-256 digest of the single-use confirmation token (never the token), mirroring
    -- recovery_flows.cancel_token_digest.
    confirm_token_digest bytea       NOT NULL,
    -- The single-use latch: NULL until the contact confirms, then the confirmation instant.
    -- A row with confirmed_at set is spent; the same token can never confirm twice.
    confirmed_at         timestamptz,
    -- The confirmation-link expiry horizon.
    expires_at           timestamptz NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recovery_contact_confirmations_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_contact_confirmations_scope_idx
    ON recovery_contact_confirmations (tenant_id, environment_id);
-- The per-flow confirmation read (count DISTINCT confirmed contacts for the threshold).
CREATE INDEX recovery_contact_confirmations_flow_idx
    ON recovery_contact_confirmations (tenant_id, environment_id, flow_id);
-- The single-use token resolution (the confirm handler resolves by digest).
CREATE UNIQUE INDEX recovery_contact_confirmations_digest_idx
    ON recovery_contact_confirmations (tenant_id, environment_id, confirm_token_digest);
-- The NO-DOUBLE-COUNT invariant: one contact confirms a flow at most once, so a single
-- contact can never reach a threshold of two by confirming twice.
CREATE UNIQUE INDEX recovery_contact_confirmations_flow_contact_uniq
    ON recovery_contact_confirmations (tenant_id, environment_id, flow_id, contact_id);

ALTER TABLE recovery_contact_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_contact_confirmations FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_contact_confirmations_tenant_isolation ON recovery_contact_confirmations
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane inserts the pending confirmations (INSERT), reads them (SELECT), and
-- LATCHES a confirmation (a column-scoped UPDATE of exactly confirmed_at). Runtime recovery
-- state: no control-plane grant.
GRANT SELECT, INSERT ON recovery_contact_confirmations TO ironauth_app;
GRANT UPDATE (confirmed_at) ON recovery_contact_confirmations TO ironauth_app;

-- ---------------------------------------------------------------------------
-- IDV-gated recovery: the external-verification session (issue #82, PR 3).
CREATE TABLE recovery_idv_sessions (
    -- The riv_ scoped identifier; embeds its (tenant, environment).
    id                   text        PRIMARY KEY,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,
    -- The recovery flow (rcv_) this session verifies (the case binding join key).
    flow_id              text        NOT NULL,
    -- The configured IDV provider slug (from the RiskConfig-style provider config).
    provider             text        NOT NULL,
    -- The single-use redirect-state nonce BOUND to the flow: the SHA-256 digest of the
    -- state the redirect carried and the callback must echo, so a callback minted for
    -- another flow's state can never complete this one.
    redirect_state_digest bytea      NOT NULL,
    -- The case nonce the callback must carry to bind it to this session (the case binding).
    callback_nonce       text        NOT NULL,
    -- The single-use latch: NULL until a callback is consumed, then the consume instant. A
    -- row with consumed_at set is spent; a replayed callback is rejected.
    consumed_at          timestamptz,
    -- The callback's asserted verification result ('pass' / 'fail'), set on consume. Only a
    -- 'pass' satisfies the method precondition.
    verdict              text,
    -- The session expiry horizon.
    expires_at           timestamptz NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recovery_idv_sessions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX recovery_idv_sessions_scope_idx
    ON recovery_idv_sessions (tenant_id, environment_id);
-- The per-flow session read.
CREATE INDEX recovery_idv_sessions_flow_idx
    ON recovery_idv_sessions (tenant_id, environment_id, flow_id);
-- The case-bound single-use resolution: the callback resolves the session by its
-- flow-bound state nonce, so a state minted for another flow selects no row (no cross-case).
CREATE UNIQUE INDEX recovery_idv_sessions_state_uniq
    ON recovery_idv_sessions (tenant_id, environment_id, flow_id, redirect_state_digest);

ALTER TABLE recovery_idv_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_idv_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_idv_sessions_tenant_isolation ON recovery_idv_sessions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane creates the session (INSERT), reads it (SELECT), and CONSUMES a callback (a
-- column-scoped UPDATE of exactly the single-use latch and the recorded verdict). Runtime
-- recovery state: no control-plane grant.
GRANT SELECT, INSERT ON recovery_idv_sessions TO ironauth_app;
GRANT UPDATE (consumed_at, verdict) ON recovery_idv_sessions TO ironauth_app;
