-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- OIDC authorization-code grant persistence (issue #12).
--
-- Three tenant-scoped tables, isolated exactly like `clients`: mandatory
-- tenant_id and environment_id, the nonempty-scope CHECK, forced row-level
-- security keyed on the same transaction-local session variables, and the same
-- foreign keys. They are reached only through the data-plane scoped repository
-- (ironauth_app), so the OIDC endpoints on the PUBLIC listener stay confined to
-- the isolation layer just like every other data-plane surface.
--
--   1. grants: the revocation spine. Links a code to its session, its consent,
--      and every token issued from it. Revoking the chain (revoked_at) flips the
--      observable active state of every token already issued from a reused code
--      (it does not cryptographically invalidate an already-minted JWT).
--   2. authorization_codes: the single-use codes. Every code binds its
--      client_id, redirect_uri, nonce, and PKCE code_challenge, so the token
--      endpoint re-checks every binding at redemption. Single use is enforced by
--      one atomic UPDATE that consumes the code (consumed_at) only while it is
--      still NULL; zero rows affected is a miss that is then classified (a benign
--      within-grace retry, a genuine reuse, or an expired/absent code), detected
--      across N stateless nodes without any in-memory marker.
--   3. issued_tokens: the jti of each access or ID token, recorded against its
--      grant, so grant-chain revocation is observable (a token is active only
--      while its issued row exists and its grant is not revoked).
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. All
-- three do so below.

-- ---------------------------------------------------------------------------
-- The grant: the revocation spine linking a code, its session, its consent, and
-- every token issued from it. A NULL revoked_at means live; a non-NULL value is
-- the revocation instant (from the application clock seam, never the database
-- clock). session_ref and consent_ref are nullable text handles: the session and
-- consent surfaces land in later M2 issues, so the grant carries the columns
-- from day one but does not require them yet.
CREATE TABLE grants (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The OAuth client the grant was issued to (a cli_ scoped identifier).
    client_id      text        NOT NULL,
    -- The authenticated end-user subject the tokens are minted for.
    subject        text        NOT NULL,
    -- The authenticating session and the recorded consent (seams for later M2).
    session_ref    text,
    consent_ref    text,
    -- Soft revocation of the whole chain: NULL is live, non-NULL is the instant.
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT grants_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The composite key the child tables' isolation-preserving FKs reference, so
    -- a code or token can only point at a grant in its OWN tenant and environment
    -- (a bare id reference would let a child bind a grant in another scope).
    UNIQUE (id, tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX grants_scope_idx ON grants (tenant_id, environment_id);

ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants FORCE ROW LEVEL SECURITY;
CREATE POLICY grants_tenant_isolation ON grants
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT/UPDATE: revocation is an UPDATE of revoked_at. No DELETE grant,
-- so a grant (and its revocation history) is never hard-deleted.
GRANT SELECT, INSERT, UPDATE ON grants TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The single-use authorization code.
--
-- The id is the ac_ code itself: a scoped identifier that embeds its
-- (tenant, environment) in the clear, so the token endpoint recovers the scope
-- from the presented code without a database lookup, and its 128-bit unique
-- component is cryptographically random (from the entropy seam). Every code binds
-- the client_id, redirect_uri, nonce, and PKCE code_challenge presented at the
-- authorization endpoint; the token endpoint re-checks each binding.
--
-- Single use is one atomic statement: the token endpoint runs `UPDATE ... SET
-- consumed_at = <now> WHERE id = $1 AND consumed_at IS NULL AND expires_at >
-- <now> RETURNING ...`. Under READ COMMITTED (pinned in begin_scoped) Postgres
-- serializes concurrent updates of the one row, so exactly one exchange sees
-- consumed_at NULL and succeeds; the rest block, re-read the committed row, and
-- affect zero rows. No in-memory marker is involved, so it holds across N
-- stateless nodes. A future cache-based accelerator can front this without
-- changing the authoritative constraint (a seam, not built here).
--
-- Clock-skew note: expires_at and consumed_at are both written and compared with
-- <now> read from each node's application clock seam, never the database clock.
-- Across N stateless nodes a code's usable lifetime and the reuse-grace boundary
-- can therefore shift by up to the inter-node clock skew. Keep nodes NTP-synced
-- and the code TTL (default 60s) well above expected skew.
CREATE TABLE authorization_codes (
    id                    text        PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- The grant this code belongs to (its revocation spine).
    grant_id              text        NOT NULL,
    -- Bindings re-checked at redemption (RFC 6749 4.1.3, RFC 9700).
    client_id             text        NOT NULL,
    redirect_uri          text        NOT NULL,
    nonce                 text,
    code_challenge        text,
    code_challenge_method text,
    -- The authenticated subject and the requested OAuth scope value.
    subject               text        NOT NULL,
    oauth_scope           text,
    -- Lifetime and single-use marker, both from the application clock seam.
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT authorization_codes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The grant must exist in the SAME tenant and environment: the reference is
    -- composite (grant_id, tenant_id, environment_id), so a code can never bind a
    -- grant belonging to another scope.
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX authorization_codes_scope_idx
    ON authorization_codes (tenant_id, environment_id);
CREATE INDEX authorization_codes_grant_idx ON authorization_codes (grant_id);

ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_codes_tenant_isolation ON authorization_codes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT/UPDATE: consuming a code is an UPDATE of consumed_at. No DELETE
-- grant, so a redeemed code is retained (its consumed_at is the replay evidence).
GRANT SELECT, INSERT, UPDATE ON authorization_codes TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Issued tokens: the jti of each access or ID token, recorded against its grant.
--
-- Recording issued tokens is what makes grant-chain revocation observable to a
-- checker that consults issued state: a token counts as active only while its
-- issued row exists AND its grant is not revoked. (Revoking the grant does not
-- cryptographically invalidate an already-minted JWT; a verifier that only
-- checks the signature and expiry still accepts it until it expires. The
-- introspection/active-state path is what observes the revocation.) token_kind
-- is 'access' or 'id'. This is also the spine the M3 refresh families build on.
CREATE TABLE issued_tokens (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    grant_id       text        NOT NULL,
    -- 'access' or 'id'.
    token_kind     text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT issued_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference (same tenant and environment).
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX issued_tokens_scope_idx ON issued_tokens (tenant_id, environment_id);
CREATE INDEX issued_tokens_grant_idx ON issued_tokens (grant_id);

ALTER TABLE issued_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE issued_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY issued_tokens_tenant_isolation ON issued_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Append-only from the data plane: SELECT and INSERT, never UPDATE or DELETE. A
-- token's active state is derived from its grant's revoked_at, so a token row is
-- never mutated in place.
GRANT SELECT, INSERT ON issued_tokens TO ironauth_app;
