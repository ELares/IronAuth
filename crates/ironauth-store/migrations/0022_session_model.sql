-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The authoritative two-tier session model with fleet operations (issue #32).
--
-- The session store is the most irreversible decision in an identity provider, so
-- this migration lands the Postgres-authoritative model that supersedes the #20
-- bootstrap session (migration 0006) and closes the M4 slice of #206 (the
-- authoritative model plus hardened cookies). Sessions are the source of truth in
-- Postgres: no in-memory-only authoritative state, so a rolling restart loses
-- nothing (later milestones add strictly read-through accelerators).
--
-- Two tiers:
--
--   1. sessions (EXPANDED in place): the SSO session, one per (subject, environment).
--      This migration EXPANDS the existing 0006 sessions table rather than replacing
--      it, so the read path, the RLS policy, and the existing scoped repository are
--      untouched and every additive column is safe for the old binary. It gains
--      revocation state (revoked_at + revoke_reason), rotation lineage (superseded_by,
--      so a rotated id STOPS resolving), the session-expiry columns this issue OWNS
--      (idle_expires_at, absolute_expires_at, ended_at, end_cause), and searchable
--      metadata for fleet ops (last_seen_at) plus the two OFF-BY-DEFAULT binding
--      columns (user_agent, peer_ip), each written only when its knob is enabled.
--
--   2. client_sessions (NEW): the per-client session, keyed to one SSO session. It
--      carries the per-(client, session) `sid` claim value: STORED (never derived as
--      sid = session_id, which would leak cross-client correlation to colluding RPs
--      and break per-client back-channel targeting), so it is STABLE for the lifetime
--      of the (client, session) pair (read straight back on every token refresh) and
--      DISTINCT across clients of the same SSO session (each pair is its own row with
--      its own random `sid`). This is the join key OIDC Back-Channel Logout needs, and
--      the reason discovery can truthfully advertise
--      backchannel_logout_session_supported.
--
-- refresh_families (issue #21) already carries `subject`, `client_id`, and
-- `session_ref`; this migration only adds the search indexes that make token-family
-- fleet ops first-class.
--
-- Fleet operations run on the management API (issue #11), which connects as the
-- least-privilege control-plane role (ironauth_control). Like the DCR abuse-controls
-- migration (0018) crossing onto the data-plane `clients` table, this migration grants
-- ironauth_control the COLUMN-SCOPED access the fleet-ops surfaces need on the
-- data-plane session and refresh tables, never a table-wide UPDATE (the #31 lesson).
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (client_sessions) ENABLEs and FORCEs row-level security, adds the (tenant,
-- environment) isolation policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. The sessions expand and the refresh_families indexes are
-- additive (columns are defaulted or nullable, indexes are additive), safe for the
-- old binary to ignore. All statements are additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. Expand the SSO session (sessions) with the M4 lifecycle and metadata.
--
-- Every column is nullable or defaulted, so the old binary (which names none of
-- them) is unaffected. revoked_at / revoke_reason flip the session inactive
-- IMMEDIATELY (the read guard rejects a revoked session regardless of expiry, so an
-- expiry-only check can never silently no-op a logout). superseded_by records the
-- successor after a session-fixation-defense rotation, so a rotated id stops
-- resolving. idle_expires_at / absolute_expires_at are the idle and hard-cap
-- lifetimes (this issue OWNS these); ended_at / end_cause record why and when a
-- session ended (this issue OWNS these). last_seen_at / user_agent are searchable
-- metadata; user_agent / peer_ip back the two OFF-BY-DEFAULT binding knobs (each is
-- written only when its knob is enabled, so the safe default records neither).
ALTER TABLE sessions
    ADD COLUMN revoked_at          timestamptz,
    ADD COLUMN revoke_reason       text,
    ADD COLUMN superseded_by       text,
    ADD COLUMN idle_expires_at     timestamptz,
    ADD COLUMN absolute_expires_at timestamptz,
    ADD COLUMN ended_at            timestamptz,
    ADD COLUMN end_cause           text,
    ADD COLUMN last_seen_at        timestamptz,
    ADD COLUMN user_agent          text,
    ADD COLUMN peer_ip             text;

-- Backfill the new lifetime columns for any pre-#32 row from its single expires_at,
-- so the read guard's COALESCE(absolute_expires_at, expires_at) and idle check stay
-- correct across the expand. A no-op on an empty table (the greenfield case).
UPDATE sessions
    SET absolute_expires_at = expires_at,
        idle_expires_at     = expires_at
    WHERE absolute_expires_at IS NULL;

-- The composite key client_sessions references, so a per-client session can never
-- bind an SSO session of another scope (the isolation-preserving reference target).
-- Additive: `id` is already the primary key, so this only exposes the (id, scope)
-- tuple for the foreign key below.
ALTER TABLE sessions
    ADD CONSTRAINT sessions_id_scope_key UNIQUE (id, tenant_id, environment_id);

-- Fleet-ops search: list sessions by subject within scope.
CREATE INDEX sessions_subject_idx ON sessions (tenant_id, environment_id, subject);

-- The data-plane role rotates (superseded_by, ended_at, end_cause) and revokes
-- (revoked_at, revoke_reason, ended_at, end_cause), and SLIDES the idle window on an
-- active session (idle_expires_at, last_seen_at), which is what makes the idle timeout
-- an IDLE timeout rather than a second absolute cap. Least privilege: COLUMN-scoped
-- UPDATE only, never table-wide (the #31 lesson).
GRANT UPDATE (revoked_at, revoke_reason, superseded_by, ended_at, end_cause,
              idle_expires_at, last_seen_at)
    ON sessions TO ironauth_app;

-- The control-plane role (the fleet-ops management surfaces) reads sessions and
-- revokes them (a single-session revoke, a bulk revoke, and revoke-everything-for-a-
-- user). COLUMN-scoped UPDATE only.
GRANT SELECT ON sessions TO ironauth_control;
GRANT UPDATE (revoked_at, revoke_reason, ended_at, end_cause) ON sessions TO ironauth_control;

-- ---------------------------------------------------------------------------
-- 2. The per-client session (client_sessions): the sid tier (issue #32).
--
-- id is a cse_ scoped identifier (embeds its (tenant, environment)). session_id is
-- the SSO session (ses_) this per-client session hangs off. sid is the STORED
-- per-(client, session) value emitted as the ID token `sid` claim: opaque, drawn
-- from the entropy seam, UNIQUE within scope, so it is stable per pair and distinct
-- across pairs. revoked_at / revoke_reason let a per-client session be ended
-- independently (per-client back-channel targeting).
CREATE TABLE client_sessions (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The SSO session (a ses_ id) this per-client session belongs to.
    session_id     text        NOT NULL,
    -- The OAuth client this per-client session is for.
    client_id      text        NOT NULL,
    -- The per-(client, session) `sid` claim value: opaque, from the entropy seam,
    -- stored so it is stable across refreshes and distinct across clients.
    sid            text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz,
    -- Set when this per-client session is ended (independently of the SSO session).
    revoked_at     timestamptz,
    revoke_reason  text,
    CONSTRAINT client_sessions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One per-client session per (SSO session, client): the sid ensure is idempotent
    -- against this key, so a re-issue for the same pair reuses the same sid.
    UNIQUE (tenant_id, environment_id, session_id, client_id),
    -- The sid is unique within scope, so it is a first-class lookup key (and can never
    -- collide across two clients of the same SSO session).
    UNIQUE (tenant_id, environment_id, sid),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the SSO session must exist in the SAME
    -- tenant and environment.
    FOREIGN KEY (session_id, tenant_id, environment_id)
        REFERENCES sessions (id, tenant_id, environment_id)
);

CREATE INDEX client_sessions_scope_idx
    ON client_sessions (tenant_id, environment_id);
-- Fleet-ops search: list per-client sessions by their SSO session, and by client.
CREATE INDEX client_sessions_session_idx
    ON client_sessions (tenant_id, environment_id, session_id);
CREATE INDEX client_sessions_client_idx
    ON client_sessions (tenant_id, environment_id, client_id);

ALTER TABLE client_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY client_sessions_tenant_isolation ON client_sessions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data-plane role creates a per-client session (the sid ensure), reads it, stamps
-- last_seen_at, and revokes it. It also CARRIES a per-client session forward onto the
-- successor session when the SAME subject re-authenticates (session_id), which is what
-- keeps the `sid` stable across a re-authentication and keeps the pre-rotation lineage
-- reachable by a later revoke instead of orphaning it. COLUMN-scoped UPDATE only (the
-- #31 lesson).
GRANT SELECT, INSERT ON client_sessions TO ironauth_app;
GRANT UPDATE (session_id, last_seen_at, revoked_at, revoke_reason)
    ON client_sessions TO ironauth_app;

-- The control-plane role (fleet ops) reads per-client sessions and revokes them.
GRANT SELECT ON client_sessions TO ironauth_control;
GRANT UPDATE (revoked_at, revoke_reason) ON client_sessions TO ironauth_control;

-- ---------------------------------------------------------------------------
-- 3. Make refresh-token families first-class fleet resources (issue #32).
--
-- refresh_families (issue #21) already carries subject, client_id, and session_ref;
-- these additive indexes make the fleet-ops search (by user, by client) first-class.
-- The revoke-everything-for-a-user cascade also queries by subject.
CREATE INDEX refresh_families_subject_idx
    ON refresh_families (tenant_id, environment_id, subject);
CREATE INDEX refresh_families_client_idx
    ON refresh_families (tenant_id, environment_id, client_id);

-- The control-plane role (the revoke-everything-for-a-user cascade) reads refresh
-- families and revokes them (COLUMN-scoped UPDATE of revoked_at only). The
-- offline_access families are preserved by the query's `offline = false` filter unless
-- the caller asks for a hard kill; the app role already holds table-wide UPDATE here
-- from issue #21, so only the control role needs a grant added.
GRANT SELECT ON refresh_families TO ironauth_control;
GRANT UPDATE (revoked_at) ON refresh_families TO ironauth_control;

-- The hard-kill cascade additionally revokes the OFFLINE families' grants, so their
-- already-issued access tokens (which derive their active state from grants.revoked_at)
-- die immediately. The control role needs to read a grant's id and set its revoked_at;
-- COLUMN-scoped UPDATE only.
GRANT SELECT ON grants TO ironauth_control;
GRANT UPDATE (revoked_at) ON grants TO ironauth_control;
