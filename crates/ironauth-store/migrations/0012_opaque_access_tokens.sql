-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Opaque access tokens: digest-only reference-token storage (issue #29).
--
-- An opaque access token is a high-entropy random string (>= 256 bits, drawn
-- from the ironauth-env entropy seam) with the scannable prefix `ira_at_`. It
-- carries no self-contained claims: unlike an at+jwt it CANNOT be validated
-- offline. The only thing stored is a SHA-256 DIGEST of the token plus the
-- token's metadata; the token itself is NEVER written to the database. So a
-- database dump contains nothing that can be replayed as a valid token (the
-- digest is one-way, and hashing any stored field does not reproduce the
-- presented token). Verification is exclusively a store lookup: the presented
-- token is hashed and matched against `token_digest` within scope, returning the
-- active claims when the row exists, its grant is not revoked, and it has not
-- expired.
--
-- The HTTP introspection endpoint (RFC 7662) that exposes this over the wire is
-- issue #22; this migration ships only the storage the internal resolve reads.
--
-- Tenant-scoped and isolated exactly like the OIDC grant tables: mandatory
-- tenant_id and environment_id, the nonempty-scope CHECK, forced row-level
-- security keyed on the same transaction-local session variables, the same
-- isolation-preserving foreign keys, and reachable only through the data-plane
-- scoped repository (ironauth_app).
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh.
-- opaque_access_tokens does all four.

CREATE TABLE opaque_access_tokens (
    -- The SHA-256 hex digest of the presented token. The lookup key: the resolve
    -- path hashes the presented token and matches it here. Unique (globally, and
    -- therefore within any scope) because the token has >= 256 bits of entropy.
    -- The plaintext token is NEVER stored: only this one-way digest.
    token_digest   text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The grant this token was issued from (the revocation spine), where
    -- applicable. NULL for a token minted outside the authorization-code flow; a
    -- non-NULL value ties the token to its grant so grant-chain revocation flips
    -- it inactive, exactly as issued_tokens does for at+jwt.
    grant_id       text,
    -- The authenticated end-user subject the token was minted for.
    subject        text        NOT NULL,
    -- The OAuth client the token belongs to (the RFC 9068 client_id equivalent).
    client_id      text        NOT NULL,
    -- The audience the token targets (a resource server's audience, or the client
    -- id for the no-resource-server case).
    audience       text        NOT NULL,
    -- The granted OAuth scope value, if any.
    scope          text,
    -- The token's logical identifier (a tok_ scoped id), unique per environment.
    -- A non-secret handle for introspection/audit correlation; it is NOT the
    -- token and is not replayable.
    jti            text        NOT NULL,
    -- The token's expiry, from the application clock seam (never the database
    -- clock), so resolution is deterministic under a manual clock in tests.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT opaque_access_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    UNIQUE (tenant_id, environment_id, jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the grant (when present) must
    -- exist in the SAME tenant and environment, so a token can never bind a grant
    -- belonging to another scope.
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX opaque_access_tokens_scope_idx
    ON opaque_access_tokens (tenant_id, environment_id);
CREATE INDEX opaque_access_tokens_grant_idx ON opaque_access_tokens (grant_id);

ALTER TABLE opaque_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE opaque_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY opaque_access_tokens_tenant_isolation ON opaque_access_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Append-only from the data plane: SELECT and INSERT, never UPDATE or DELETE. A
-- token's active state is derived from its grant's revoked_at and its expiry, so
-- a token row is never mutated in place.
GRANT SELECT, INSERT ON opaque_access_tokens TO ironauth_app;
