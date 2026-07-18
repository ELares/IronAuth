-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Signup fraud review queue: the users.quarantined flag and the signup_quarantines
-- review table (issue #82, PR 2).
--
-- The DCR client quarantine (issue #31) applies to a REGISTERED CLIENT: an unverified
-- client stays usable but restricted (consent is always shown, its first-party
-- carve-out is ignored) until an admin verifies it. This migration mirrors that exact
-- mental model to a HUMAN SIGNUP: a registration the risk path would otherwise BLOCK
-- (a disposable-domain block or a failed proof-of-work challenge, issue #80) can
-- instead be QUARANTINED so a false positive is RECOVERABLE. The account exists and can
-- authenticate, but with limited privileges: consent is ALWAYS re-prompted and every
-- SENSITIVE scope (offline_access, an admin/management scope, a configured payment-class
-- scope) is stripped from any grant, until an admin RELEASES it from the review queue.
--
--   users.quarantined: a boolean ORTHOGONAL to the user's lifecycle state, exactly like
--     clients.quarantined (0018:222). The account stays UserState::Active
--     (can_authenticate() true, UNLIKE a Waitlisted signup which cannot authenticate),
--     so a quarantined user CAN log in; the flag is the orthogonal restriction the
--     authorize path enforces (consent-always-on + sensitive-scope strip). The data
--     plane sets it at INSERT (a quarantined signup is created quarantined) but can
--     NEVER clear it: only the control plane's column-scoped UPDATE below lifts a
--     quarantine, so a quarantined user has no data-plane path to self-approve.
--
--   signup_quarantines: one review-queue row per quarantined signup.
--     - a scope-embedded `sqn_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - subject: the quarantined `usr_` id the case is about, the anti-IDOR filter the
--       admin read and the release/reject/extend writes key on;
--     - reason: WHY the signup was quarantined, pinned to a closed set (a disposable /
--       risk-output block, or a failed registration challenge);
--     - risk_context: an OPTIONAL operator-legibility note (non-secret metadata, never
--       a credential or raw PII), so the admin queue is readable;
--     - state: the review position, pinned to a closed set. `pending` and `extended` are
--       the OPEN states (the account stays quarantined); `approved` released it (the
--       admin cleared users.quarantined) and `rejected` cleaned the account up;
--     - quarantined_until: the extend-window horizon (NULL = an indefinite pending case),
--       bumped by the admin EXTEND action from the application clock seam;
--     - reviewed_by_kind / reviewed_by_id: the APPROVING/REJECTING/EXTENDING admin actor,
--       stamped once a review action runs, so the queue answers WHO decided a case
--       (the audit_log carries the same attribution; this is the inline copy the admin
--       list surfaces);
--     - reviewed_at: the instant the review action ran (the application clock seam);
--     - review_note: an OPTIONAL operator note recorded with a review decision.
--
--     Runtime data (issue #41): a signup-quarantine case is dynamic per-environment risk
--     state (like a risk_decision or a recovery_flow), NEVER promotable config, so it
--     STRUCTURALLY never enters a config snapshot (only Promotable types are exported)
--     and carries no first-class ResourceType variant. There is no control-plane SELECT
--     grant beyond the review columns' UPDATE: a quarantine case is runtime risk state,
--     never part of an account export.
--
-- The partial UNIQUE (tenant, environment, subject) WHERE state IN ('pending','extended')
-- is the one-open-case-per-account invariant: an account has at most one OPEN review case
-- at a time, so re-opening a case for an already-quarantined subject is a structural
-- conflict rather than a silent duplicate.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped signup_quarantines
-- table ENABLES and FORCES row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. The
-- users.quarantined ALTER is additive with a DEFAULT, so it back-fills every existing row
-- to the safe unquarantined value. Every statement is additive, so this migration is an
-- EXPAND.

-- ---------------------------------------------------------------------------
-- The orthogonal quarantine flag on the human account (issue #82, PR 2), mirroring
-- clients.quarantined (0018). Additive with a DEFAULT: every existing account back-fills
-- to false (unquarantined), so the flag changes no existing account's behavior.
ALTER TABLE users
    ADD COLUMN quarantined boolean NOT NULL DEFAULT false;

-- The control plane (the admin review queue) LIFTS a quarantine (an UPDATE of exactly the
-- quarantined column) when it releases a case; the data plane can never clear it. A
-- clients-style column-scoped grant is the enforcement: users has NO table-wide UPDATE
-- (its grants are per-column and additive, 0037:104), so the new quarantined column is
-- unwritable by ironauth_app by default. The data plane still SETS quarantined=true at
-- INSERT (its SELECT, INSERT grant covers a full-row insert), so a quarantined signup is
-- created quarantined; it simply has no UPDATE privilege to ever flip it back. Granting
-- the control plane exactly UPDATE(quarantined) is the whole self-approval-impossible
-- guarantee: only an admin release can lift a quarantine.
GRANT UPDATE (quarantined) ON users TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The signup fraud review queue (issue #82, PR 2).
CREATE TABLE signup_quarantines (
    -- The sqn_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The quarantined usr_ id the case is about (the anti-IDOR filter).
    subject           text        NOT NULL,
    -- Why the signup was quarantined, a closed set.
    reason            text        NOT NULL,
    -- An OPTIONAL operator-legibility note (non-secret metadata, never a credential).
    risk_context      text,
    -- The review position, a closed set. pending/extended are the OPEN states.
    state             text        NOT NULL DEFAULT 'pending',
    -- The extend-window horizon (NULL = an indefinite pending case).
    quarantined_until timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- The approving/rejecting/extending admin actor, stamped once a review action runs.
    reviewed_by_kind  text,
    reviewed_by_id    text,
    reviewed_at       timestamptz,
    -- An OPTIONAL operator note recorded with a review decision.
    review_note       text,
    CONSTRAINT signup_quarantines_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed reason set: an unknown reason can never be written.
    CONSTRAINT signup_quarantines_reason_known
        CHECK (reason IN ('risk_output', 'challenge_failure')),
    -- The closed review-state set: an unknown state can never be written.
    CONSTRAINT signup_quarantines_state_known
        CHECK (state IN ('pending', 'approved', 'rejected', 'extended')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX signup_quarantines_scope_idx
    ON signup_quarantines (tenant_id, environment_id);
-- The admin review-queue keyset read (open cases, newest first, over (created_at, id)).
CREATE INDEX signup_quarantines_queue_idx
    ON signup_quarantines (tenant_id, environment_id, state, created_at, id);
-- The one-open-case-per-account invariant: an account has at most one OPEN (pending or
-- extended) review case, so re-quarantining an already-open subject is a structural
-- conflict, not a silent duplicate.
CREATE UNIQUE INDEX signup_quarantines_open_uniq
    ON signup_quarantines (tenant_id, environment_id, subject)
    WHERE state IN ('pending', 'extended');

ALTER TABLE signup_quarantines ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_quarantines FORCE ROW LEVEL SECURITY;
CREATE POLICY signup_quarantines_tenant_isolation ON signup_quarantines
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane OPENS a case (INSERT) when it quarantines a risky signup, and reads it
-- back (SELECT). The control plane (the admin review queue) READS the queue (SELECT) and
-- OWNS the verdict: a COLUMN-SCOPED UPDATE over exactly the review columns
-- (state / quarantined_until / the reviewer stamp / the note), so the data plane can
-- never move a case forward and the control plane can never rewrite the case's identity
-- (its subject or reason). This mirrors the #31 split: the data plane creates, the
-- control plane decides.
GRANT SELECT, INSERT ON signup_quarantines TO ironauth_app;
GRANT SELECT ON signup_quarantines TO ironauth_control;
GRANT UPDATE (
        state, quarantined_until, reviewed_by_kind, reviewed_by_id, reviewed_at,
        review_note
    ) ON signup_quarantines TO ironauth_control;
