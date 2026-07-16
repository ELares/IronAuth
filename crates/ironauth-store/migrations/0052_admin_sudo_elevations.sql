-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Session privilege separation for the admin surface: the recorded re-authentication
-- (sudo) elevation ledger (issue #73).
--
-- Sudo mode bounds what a stolen admin credential can do: a read is always allowed,
-- but a mutation requires a RECENT re-authentication. The freshness is evaluated the
-- same way the step-up path (issue #72) evaluates a max-auth-age window, against a
-- recorded auth_time that DERIVES FROM A SERVER-WRITTEN RE-AUTH EVENT and never from a
-- client-supplied header or flag (the #14/#72 acr honesty discipline). This migration
-- lands the one piece of persistent state that guarantee needs:
--
--   admin_sudo_elevations: an append-only ledger of privilege-elevation events. One
--   row is written each time an admin credential completes a re-authentication for a
--   (tenant, environment): the acting principal (actor kind + id), the achieved acr,
--   the recorded elevation instant, and the window's expiry. The mutation guard reads
--   the LATEST row for the acting principal and treats the elevation as fresh only
--   while `now < expires_at`; an absent or lapsed row fails closed (a challenge). The
--   ledger is also the audit trail (every elevation is a durable row), so the "who
--   elevated when" record and the freshness source are the SAME server-side state,
--   which is exactly why the state can never be client-asserted.
--
-- The seam is deliberately NOT admin-only: the row keys on the acting principal within
-- a scope, so an end-user application adopting the same mechanism later reads the same
-- ledger for its own subject. The prototype grants only the CONTROL-plane role, which
-- is the role the management API connects as.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table ENABLEs and
-- FORCEs row-level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The admin sudo elevation ledger (issue #73).
--
-- id is an `elv_` scoped identifier (embeds its (tenant, environment)), the audit
-- target. actor_kind / actor_id name the acting principal the elevation belongs to
-- (the management service actor), so the mutation guard can read the latest elevation
-- for exactly the credential presenting the request. acr is the achieved
-- authentication context of the re-auth (an honest, server-derived value, never a
-- request parameter). elevated_at is the recorded re-authentication instant and
-- expires_at is `elevated_at + the per-environment window`, denormalized so the read
-- path needs no window arithmetic and a prune can sweep by expiry. The row is
-- INSERT-only: an elevation is a historical fact, never edited.
-- ---------------------------------------------------------------------------
CREATE TABLE admin_sudo_elevations (
    id             text        NOT NULL,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The acting principal's audit-actor kind (e.g. 'service') and id.
    actor_kind     text        NOT NULL,
    actor_id       text        NOT NULL,
    -- The achieved authentication context of the recorded re-auth (a public acr
    -- string, derived server-side, never a client-asserted value).
    acr            text        NOT NULL,
    -- The recorded re-authentication instant (the freshness source).
    elevated_at    timestamptz NOT NULL,
    -- elevated_at + the per-environment window, denormalized for the read and prune.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admin_sudo_elevations_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT admin_sudo_elevations_actor_nonempty
        CHECK (actor_kind <> '' AND actor_id <> ''),
    CONSTRAINT admin_sudo_elevations_acr_nonempty
        CHECK (acr <> ''),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX admin_sudo_elevations_scope_idx
    ON admin_sudo_elevations (tenant_id, environment_id);
-- The guard reads the LATEST elevation for an actor: scope + actor, newest first.
CREATE INDEX admin_sudo_elevations_actor_idx
    ON admin_sudo_elevations (tenant_id, environment_id, actor_id, elevated_at DESC);

ALTER TABLE admin_sudo_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sudo_elevations FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_sudo_elevations_tenant_isolation ON admin_sudo_elevations
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The management (control) plane records an elevation (INSERT), reads the latest one
-- for the acting principal (SELECT), and prunes expired rows (DELETE). No UPDATE: the
-- ledger is append-only, so there is no column-scoped UPDATE grant to name (the #31
-- least-privilege lesson is satisfied by granting no UPDATE at all).
GRANT SELECT, INSERT, DELETE ON admin_sudo_elevations TO ironauth_control;
