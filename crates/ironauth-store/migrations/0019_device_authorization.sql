-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Device authorization grant (issue #24, RFC 8628) with cross-device BCP
-- mitigations.
--
-- A constrained device (a CLI, a TV, an IoT device) starts a flow at the
-- back-channel device-authorization endpoint and receives a device_code (a
-- machine credential it polls the token endpoint with) plus a user_code (a short,
-- transcription-friendly code a human types into the verification page). This
-- migration ships the single tenant-scoped table both halves live in, plus the two
-- per-client columns the verification page and the grant allowlist read.
--
-- Credential-at-rest discipline (RFC 8628 sections 5.1, 6.1):
--
--   * device_code_digest is the SHA-256 DIGEST of the WHOLE device code
--     (`ira_dc_<jti>~<secret>`), never the plaintext. The device code declares its
--     own (tenant, environment) scope through the embedded jti, exactly like an
--     opaque access token (issue #29), so the GLOBAL /token endpoint recovers the
--     scope and runs this RLS-scoped digest resolve. A database dump yields nothing
--     replayable: the digest is one-way and the 256-bit secret suffix never lands.
--   * user_code_hash is the SHA-256 hash of the NORMALIZED user code (uppercased,
--     separators stripped), never the plaintext. The verification page hashes the
--     submitted code and matches it here. High entropy from a restricted alphabet
--     plus a short TTL plus per-code and per-source rate limits make brute forcing
--     the code space infeasible within the code's lifetime.
--
-- Neither the device code nor the user code is ever stored or logged in plaintext.
--
-- Tenant-scoped and isolated exactly like the OIDC grant tables: mandatory
-- tenant_id and environment_id, the nonempty-scope CHECK, forced row-level
-- security keyed on the same transaction-local session variables, isolation-
-- preserving foreign keys, and reachable only through the scoped repository
-- (ironauth_app).
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy and
-- the nonempty-scope CHECK, and is registered in scripts/query-audit.sh.
-- device_codes does all four. The clients ALTERs are additive and default to the
-- pre-#24 behavior (only the authorization_code grant, no logo).

CREATE TABLE device_codes (
    -- The SHA-256 hex digest of the WHOLE presented device code. The poll lookup
    -- key: the token endpoint hashes the presented device code and matches it here.
    -- Unique because the device code carries >= 256 bits of entropy. The plaintext
    -- device code is NEVER stored: only this one-way digest.
    device_code_digest text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The flow's logical identifier (a dc_ scoped id, the routing handle embedded in
    -- the device code). A NON-secret handle (the secret is the device code's 256-bit
    -- suffix, and only its digest is stored above): the verification page carries it
    -- to bind the human's approval to a flow WITHOUT ever seeing the device code, and
    -- it is the audit target. Unique per environment.
    id                 text        NOT NULL,
    -- The SHA-256 hex hash of the NORMALIZED user code. The verification page
    -- matches a submitted user code by hashing it and looking it up here. Unique
    -- within scope so a user code resolves to exactly one flow.
    user_code_hash     text        NOT NULL,
    -- The OAuth client (a cli_ scoped id string) the flow belongs to.
    client_id          text        NOT NULL,
    -- The OAuth scope requested at the device-authorization endpoint, echoed into
    -- the issued tokens, or NULL when the request carried none.
    requested_scope    text,
    -- The flow lifecycle: pending (awaiting approval), approved (a human confirmed;
    -- the next poll issues tokens), denied (a human rejected it, or the user code
    -- exhausted its failed-match budget), expired (past its TTL), redeemed (tokens
    -- already issued; a further poll is invalid_grant).
    status             text        NOT NULL DEFAULT 'pending',
    -- The current minimum polling interval in seconds (RFC 8628 section 3.5). Starts
    -- at the configured default and is INCREASED in place each time the device polls
    -- faster than the current interval, so slow_down is enforced per device_code.
    interval_secs      integer     NOT NULL,
    -- The instant of the device's most recent poll (from the application clock seam,
    -- never the database clock), or NULL before the first poll. The slow_down check
    -- compares the next poll against this plus interval_secs.
    last_poll_at       timestamptz,
    -- Failed user-code match attempts attributable to this flow (RFC 8628 section
    -- 5.1). When it reaches the configured bound the flow is invalidated (status ->
    -- denied), so a user code cannot be brute forced by repeated guessing.
    failed_attempts    integer     NOT NULL DEFAULT 0,
    -- A coarse, operator-safe hint of where the flow was initiated (the initiating
    -- request's network source), shown on the verification page so a human can
    -- recognize a flow they did not start (the cross-device BCP anti-phishing cue).
    -- NULL when no source was observed.
    initiation_hint    text,
    -- The authenticated end-user subject (a usr_ id string) bound at approval, or
    -- NULL while pending. Set together with the grant in one transaction.
    subject            text,
    -- The grant opened at approval (the revocation spine the issued tokens hang
    -- off), or NULL while pending.
    grant_id           text,
    -- The consent decision recorded at approval (a con_ id string), or NULL.
    consent_ref        text,
    -- The authentication methods (space-separated RFC 8176 values) frozen from the
    -- approving human's session, the source the issued ID token's amr/acr derive
    -- from. NULL while pending.
    auth_methods       text,
    -- The approving human's authentication instant (from the application clock
    -- seam), frozen so the ID token's auth_time is truthful. NULL while pending.
    auth_time          timestamptz,
    -- The flow's expiry (from the application clock seam), after which a poll yields
    -- expired_token and the verification page shows a safe error.
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_codes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT device_codes_status_known
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'redeemed')),
    UNIQUE (tenant_id, environment_id, user_code_hash),
    UNIQUE (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the grant (when present) must exist
    -- in the SAME tenant and environment, so an approved flow can never bind a grant
    -- belonging to another scope.
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX device_codes_scope_idx ON device_codes (tenant_id, environment_id);
CREATE INDEX device_codes_grant_idx ON device_codes (grant_id);

ALTER TABLE device_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY device_codes_tenant_isolation ON device_codes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane issues a flow (INSERT), polls it and approves/denies it. Polling
-- and the approval both MUTATE the row, so unlike the append-only token tables this
-- table needs UPDATE. CRITICAL (lesson from issue #31): NEVER grant a table-wide
-- UPDATE. A table-level UPDATE auto-covers every column added later, so it would let
-- a compromised or buggy data-plane path rewrite immutable columns (the digest, the
-- user_code_hash, the client, the expiry) and relocate or extend a flow. Grant a
-- COLUMN-SCOPED UPDATE over EXACTLY the columns the data plane writes after
-- creation: the polling bookkeeping (status, interval_secs, last_poll_at,
-- failed_attempts) and the approval linkage (subject, grant_id, consent_ref,
-- auth_methods, auth_time). The device_code_digest, user_code_hash, client_id,
-- requested_scope, initiation_hint, expires_at, and created_at are write-once at
-- INSERT and stay unwritable. No DELETE: an expired flow is invalidated by status
-- and TTL, not removed here.
GRANT SELECT, INSERT ON device_codes TO ironauth_app;
GRANT UPDATE (
    status,
    interval_secs,
    last_poll_at,
    failed_attempts,
    subject,
    grant_id,
    consent_ref,
    auth_methods,
    auth_time
) ON device_codes TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Per-client device-grant allowlist and display logo (issue #24). Additive and
-- safe for the old binary: grant_types defaults to today's behavior (only the
-- authorization_code grant), and logo_uri defaults to NULL (no logo).
--
--   grant_types: the space-separated list of OAuth grant types the client is
--                permitted. The device-authorization endpoint refuses a client
--                whose list does not contain
--                'urn:ietf:params:oauth:grant-type:device_code', so the device
--                grant is opt-in per client (a grant allowlist, RFC 8628 needs the
--                grant enabled per client). The default keeps every existing client
--                on authorization_code only.
--   logo_uri:    the client's registered logo (RFC 7591 metadata), rendered as an
--                image on the verification page so a human recognizes the app. The
--                page never fetches it server-side (the browser loads it); NULL
--                shows no logo.
ALTER TABLE clients
    ADD COLUMN grant_types text NOT NULL DEFAULT 'authorization_code',
    ADD COLUMN logo_uri    text;

-- Migration 0018 revoked the table-wide UPDATE on clients from ironauth_app and
-- re-granted a COLUMN-SCOPED UPDATE over exactly the data-plane-owned columns; a new
-- clients column is therefore app-unwritable until deliberately granted (the whole
-- point of that narrowing). The device-grant allowlist and the logo are data-plane
-- configuration, so ADD them to the data plane's column-scoped UPDATE. This is an
-- additive GRANT (Postgres unions column privileges), so it does not touch the 0018
-- grant. The control-plane-only quarantine columns stay unwritable to the data plane.
GRANT UPDATE (grant_types, logo_uri) ON clients TO ironauth_app;
