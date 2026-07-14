-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Refresh token rotation, families, offline_access, and consent modes (issue #21).
--
-- This migration lands the storage behind rotating refresh tokens with reuse
-- detection (RFC 9700 2.2.2, OAuth 2.1), the offline_access lifecycle (OIDC Core
-- 11, Back-Channel Logout 2.7), and per-client consent modes:
--
--   1. refresh_families: the revocation spine. Every refresh token belongs to a
--      family rooted at ONE original authorization grant. Revoking the family (a
--      genuine reuse outside the grace window, or an RP logout for a session-bound
--      family) invalidates every generation in the chain at once. The family
--      carries the hard cap on its total rotated lifetime and the exactly-once
--      reuse marker.
--   2. refresh_tokens: one row per generation. Only the SHA-256 DIGEST of the
--      whole `ira_rt_<jti>~<secret>` wire token is stored (never the token), so a
--      database dump yields nothing replayable, exactly like opaque_access_tokens.
--      A row's rotated_at marks it superseded; the digest is the lookup key.
--   3. A clients ALTER (additive) for the per-client consent mode, the skip and
--      no-store consent knobs, and the optional refresh-rotation override.
--   4. A consents ALTER (additive) for the remembered-consent expiry.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Both new tables do all four. The clients and consents
-- ALTERs are pure additive column expands (defaulted or nullable), safe for the
-- old binary to ignore.

-- ---------------------------------------------------------------------------
-- 1. The refresh-token family: the revocation spine (issue #21).
--
-- A family is rooted at one authorization grant. grant_id ties it to that grant
-- so grant-chain revocation (issue #12 code reuse, and any future grant revoke)
-- ALSO kills the family. absolute_expires_at is the hard cap on the total rotated
-- lifetime, from the application clock seam. revoked_at flips the whole family
-- inactive; reuse_detected_at records that the revocation was a genuine reuse, so
-- the typed reuse event is emitted EXACTLY once (only the transition that flips
-- revoked_at emits it). offline distinguishes an offline_access family (survives
-- RP logout) from a session-bound one; session_ref is the authenticating session
-- so an RP logout can revoke the session-bound families it owns.
CREATE TABLE refresh_families (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The grant this family is rooted at (the shared revocation spine).
    grant_id            text        NOT NULL,
    -- The authenticated end-user subject the family's tokens are minted for.
    subject             text        NOT NULL,
    -- The OAuth client the family belongs to.
    client_id           text        NOT NULL,
    -- The granted OAuth scope value the family was issued against, if any. The
    -- refreshed access token is minted for exactly this scope.
    scope               text,
    -- The recorded authentication method tokens frozen at issuance, so a refreshed
    -- access token's acr/amr derive from the original login (never re-derived).
    auth_methods        text        NOT NULL DEFAULT '',
    -- The authenticating session (a ses_ id), so an RP logout can revoke the
    -- session-bound families it owns. NULL when no session backed the grant.
    session_ref         text,
    -- Whether this is an offline_access family (survives RP logout, separate
    -- lifecycle) or a session-bound one (revoked with the session).
    offline             boolean     NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL,
    -- The hard cap on the family's total rotated lifetime, from the application
    -- clock seam. Past this instant no rotation renews the family.
    absolute_expires_at timestamptz NOT NULL,
    -- Set when the whole family is revoked (a genuine reuse, or an RP logout).
    revoked_at          timestamptz,
    -- Set alongside revoked_at ONLY when the revocation was a genuine reuse, so the
    -- typed reuse event is emitted exactly once per incident.
    reuse_detected_at   timestamptz,
    CONSTRAINT refresh_families_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The composite key refresh_tokens references, so a token can never bind a
    -- family of another scope.
    UNIQUE (id, tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the grant must exist in the SAME
    -- tenant and environment.
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX refresh_families_scope_idx
    ON refresh_families (tenant_id, environment_id);
CREATE INDEX refresh_families_grant_idx ON refresh_families (grant_id);
-- The RP-logout revoke scans session-bound families by their session.
CREATE INDEX refresh_families_session_idx
    ON refresh_families (tenant_id, environment_id, session_ref);

ALTER TABLE refresh_families ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_families FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_families_tenant_isolation ON refresh_families
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to resolve, INSERT to open a family, UPDATE to revoke it (revoked_at /
-- reuse_detected_at). No DELETE: a family is never removed, only revoked.
GRANT SELECT, INSERT, UPDATE ON refresh_families TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The refresh token: one row per generation, digest only (issue #21).
--
-- token_digest is the SHA-256 hex of the WHOLE `ira_rt_<jti>~<secret>` wire token
-- (jti is a rft_ scoped id declaring the token's scope; secret is 256 bits from
-- the entropy seam). The plaintext token is NEVER stored: a schema-level test
-- asserts no plaintext-token column exists. rotated_at marks the row superseded by
-- a successor; a presentation of a rotated token within the grace window is a
-- benign concurrent refresh, beyond it a genuine reuse. generation and
-- predecessor_jti record the rotation chain.
CREATE TABLE refresh_tokens (
    -- The SHA-256 hex digest of the presented token. The lookup key. Unique
    -- (globally, and so within any scope) because the token has 256 bits of
    -- entropy. The plaintext token is NEVER stored: only this one-way digest.
    token_digest   text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The family this generation belongs to (the revocation spine).
    family_id      text        NOT NULL,
    -- The token's logical id (a rft_ scoped id), also the routing handle embedded
    -- in the wire token. Unique per environment. NOT the token and not replayable.
    jti            text        NOT NULL,
    -- The generation counter within the family (0 for the first-issued token).
    generation     integer     NOT NULL,
    -- The jti of the token this one succeeded (NULL for generation 0).
    predecessor_jti text,
    -- When this generation was issued, from the application clock seam.
    issued_at      timestamptz NOT NULL,
    -- The idle expiry of this generation, from the application clock seam. A token
    -- unused past this instant does not resolve.
    idle_expires_at timestamptz NOT NULL,
    -- Set when this token was rotated away from (superseded). The grace-window
    -- reuse classification compares the presentation time against this.
    rotated_at     timestamptz,
    -- The jti of the successor minted when this token rotated (NULL until rotated).
    successor_jti  text,
    -- No separate created_at: issued_at already records the generation's creation
    -- instant from the application clock seam (issue #21), so a DB-clock DEFAULT now()
    -- would only diverge from that seam and be invisible to a deterministic-clock test.
    CONSTRAINT refresh_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    UNIQUE (tenant_id, environment_id, jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the family must exist in the SAME
    -- tenant and environment, so a token can never bind a family of another scope.
    FOREIGN KEY (family_id, tenant_id, environment_id)
        REFERENCES refresh_families (id, tenant_id, environment_id)
);

CREATE INDEX refresh_tokens_scope_idx
    ON refresh_tokens (tenant_id, environment_id);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to resolve, INSERT to record a generation, UPDATE to mark a token
-- rotated (rotated_at / successor_jti). No DELETE: a spent token row is kept so
-- reuse detection can still classify a later presentation of it.
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. Per-client consent modes (issue #21). Additive and safe for the old binary:
-- every column defaults to today's behavior (explicit consent, no skip, store
-- skipped consents, rotation auto by client posture).
--
--   consent_mode:    'explicit' (always prompt unless a covering consent exists),
--                    'implicit' (trusted first-party: never prompt, auto-grant),
--                    or 'remembered' (prompt, then honor the recorded consent for
--                    the remembered-consent TTL before re-prompting).
--   skip_consent:    an orthogonal quick knob: when true the consent screen is
--                    skipped and consent auto-granted, like 'implicit'.
--   store_skipped_consent: when a consent is skipped (implicit / skip_consent),
--                    whether to PERSIST a consent row. false is the Ory Hydra
--                    performance knob: skip the screen AND write no row.
--   refresh_rotation: an optional per-client override of the rotation policy:
--                    'always' (rotate on every refresh) or 'threshold' (rotate
--                    only past the configured fraction of TTL). NULL derives the
--                    policy from the client's posture (public -> always,
--                    confidential -> threshold).
ALTER TABLE clients
    ADD COLUMN consent_mode          text    NOT NULL DEFAULT 'explicit',
    ADD COLUMN skip_consent          boolean NOT NULL DEFAULT false,
    ADD COLUMN store_skipped_consent boolean NOT NULL DEFAULT true,
    ADD COLUMN refresh_rotation      text;

-- ---------------------------------------------------------------------------
-- 4. Remembered-consent expiry (issue #21). Additive nullable column. NULL means
-- the recorded consent never expires (the 'explicit' mode default); a 'remembered'
-- consent stores an expiry from the application clock seam, and a read past that
-- instant treats the consent as absent so the next authorization re-prompts.
ALTER TABLE consents ADD COLUMN expires_at timestamptz;

-- The app role holds only COLUMN-level UPDATE on consents (granted_scope, from
-- migration 0010): the re-grant upsert rewrites the scope. The remembered-consent
-- upsert now ALSO rewrites expires_at, so the role needs UPDATE on that column
-- too. Least privilege is preserved: still no table-wide UPDATE, only these two
-- columns.
GRANT UPDATE (expires_at) ON consents TO ironauth_app;
