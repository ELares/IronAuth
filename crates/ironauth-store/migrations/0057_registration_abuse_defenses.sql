-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Registration abuse defenses (issue #80).
--
-- Registration, reset, and OTP-send endpoints are free attack surface: bot signups
-- pollute the directory, OTP endpoints get pumped, and resets get farmed for
-- enumeration. The incumbent answer is a hard dependency on a third-party CAPTCHA,
-- which breaks self-hosting, air-gapped deployments, and privacy postures. IronAuth
-- adopts an invisible, self-contained proof-of-work challenge (a Rauthy-spow-style
-- hashcash) as the DEFAULT defense, with ZERO external calls; Turnstile and reCAPTCHA
-- are OPTIONAL adapters behind a pluggable interface (honoring the
-- no-mandatory-third-party-infrastructure covenant). This migration lands the durable
-- state the PoW verifier needs, plus the waitlist/pending lifecycle state.
--
--   pow_challenges: one row per issued proof-of-work challenge. The server issues a
--     random challenge and a difficulty; the client finds a nonce such that
--     hash(challenge || nonce) has N leading zero bits; the server verifies the nonce
--     meets the difficulty AND that the challenge is UNSPENT, UNEXPIRED, and
--     CONTEXT-BOUND. The challenge is NOT a secret (it is handed to the client), so it
--     is stored in the clear; the single-use latch (spent_at, set exactly once) and the
--     context_hash binding (endpoint + a request context, so a solved challenge cannot
--     be replayed or outsourced to another endpoint/context) are the security-bearing
--     columns. The challenge and its expiry come from the env clock/entropy seam, so the
--     verifier is deterministic under a manual clock in tests. This is data-plane state,
--     minted and consumed by the request path (not the management API).
--
-- The waitlist toggle gates self-service signup: with it on, a new registration lands
-- in a PENDING lifecycle state that CANNOT authenticate (the users state machine's
-- can_authenticate() fences it, exactly like blocked/disabled), and an admin APPROVES
-- it (transition to active) or REJECTS it (transition to disabled) through the existing
-- user-lifecycle management API. This migration WIDENS the closed users.state CHECK to
-- admit the new 'waitlisted' value (an additive widen, exactly like 0047 widened the
-- abuse_bans auth_path CHECK), reusing the existing state column and its grants.
--
-- The disposable / low-reputation email defense is per-environment CONFIGURATION
-- (oidc.registration_abuse.disposable_email: off / flag / block, plus deny and allow
-- override lists), so it promotes with the config snapshot and needs no table here; it
-- reuses the #79 IP allow/deny-list precedent (updateable, per-environment data that is
-- not compiled in).
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table ENABLES and
-- FORCES row-level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. The users.state
-- CHECK widen is additive. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The proof-of-work challenge state (issue #80). id is a `pow_` scoped identifier that
-- doubles as the routing handle the client returns with its nonce. challenge is the
-- random challenge bytes the server issued (NOT a secret). difficulty_bits is the number
-- of leading zero bits the client's nonce must produce. context_hash is the SHA-256 of
-- the endpoint plus the request context the challenge is BOUND to, so a solution for one
-- endpoint/context does not satisfy another (no replay, no outsourcing). spent_at is the
-- single-use latch, set exactly once when a valid solution is accepted. expires_at bounds
-- the challenge lifetime (via env.clock()).
CREATE TABLE pow_challenges (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The random challenge bytes the server issued (via env.entropy()). Not a secret:
    -- it is handed to the client, which must find a qualifying nonce for it.
    challenge           bytea       NOT NULL,
    -- The number of leading zero bits hash(challenge || nonce) must have. A per-env
    -- configured difficulty, bounded so a misconfiguration cannot wedge the endpoint.
    difficulty_bits     integer     NOT NULL,
    -- The SHA-256 of the endpoint plus the request context the challenge is bound to.
    -- Verification recomputes it from the presenting request and requires an exact
    -- match, so a solved challenge cannot be replayed to a different endpoint/context.
    context_hash        bytea       NOT NULL,
    -- The single-use latch: set exactly once when a valid solution is accepted. A row
    -- whose spent_at is non-null can never satisfy a second verification (replay-proof).
    spent_at            timestamptz,
    -- Past this instant the challenge no longer verifies (enforced authoritatively via
    -- env.clock()).
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pow_challenges_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The difficulty is a small non-negative bit count; the closed range keeps a
    -- misconfiguration from demanding an impossible or trivial amount of work.
    CONSTRAINT pow_challenges_difficulty_range
        CHECK (difficulty_bits >= 0 AND difficulty_bits <= 255),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX pow_challenges_scope_idx
    ON pow_challenges (tenant_id, environment_id);
-- A sweep of expired challenges (a future janitor) scans by expiry within a scope.
CREATE INDEX pow_challenges_expiry_idx
    ON pow_challenges (tenant_id, environment_id, expires_at);

ALTER TABLE pow_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE pow_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY pow_challenges_tenant_isolation ON pow_challenges
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane mints a challenge (INSERT), resolves a presented one (SELECT), and
-- consumes it single-use (a COLUMN-scoped UPDATE to spent_at). COLUMN-scoped UPDATE
-- only (the #31 least-privilege lesson). It also RECLAIMS its own EXPIRED rows with a
-- BOUNDED DELETE on the issue path (issue #80 LOW-3): every mint eagerly deletes a small,
-- capped batch of this scope's already-expired challenges, so a stream of `/pow/challenge`
-- calls cannot grow the table without bound and no external janitor is required. The DELETE
-- is RLS-scoped to the caller's (tenant, environment) exactly like every other grant here,
-- and only ever removes rows already past `expires_at`, so it can never reclaim a live
-- (unspent, unexpired) challenge. A heavier out-of-band sweep may still run as a separate
-- role later; this grant only enables the bounded request-path reclaim.
GRANT SELECT, INSERT, DELETE ON pow_challenges TO ironauth_app;
GRANT UPDATE (spent_at) ON pow_challenges TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Widen the closed users.state set (issue #80) to admit the waitlist 'waitlisted'
-- state: a self-service signup made while waitlist mode is on lands here and CANNOT
-- authenticate until an admin approves it (transition to active) or rejects it
-- (transition to disabled) through the existing user-lifecycle management API. This is
-- an additive widen of the CHECK the repository state machine already enforces, exactly
-- like 0047 widened the abuse_bans auth_path CHECK; the existing state column and its
-- grants are reused, so no new column, backfill, or grant is needed.
ALTER TABLE users
    DROP CONSTRAINT users_state_valid;
ALTER TABLE users
    ADD CONSTRAINT users_state_valid
        CHECK (state IN (
            'active', 'blocked', 'disabled', 'pending_verification',
            'scheduled_offboarding', 'waitlisted', 'deleted'
        ));
