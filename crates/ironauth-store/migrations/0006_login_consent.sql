-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Bootstrap login, consent, session, and secret-based client authentication
-- (issue #20).
--
-- Three new tenant-scoped tables, isolated exactly like `clients` and the OIDC
-- grant tables: mandatory tenant_id and environment_id, the nonempty-scope CHECK,
-- forced row-level security keyed on the same transaction-local session variables,
-- the same isolation-preserving foreign keys, and reachable only through the
-- data-plane scoped repository (ironauth_app). Plus an additive expand of the
-- existing `clients` table with the two columns secret-based client authentication
-- needs.
--
--   1. users: the bootstrap end-user directory. An identifier (the login handle)
--      and an Argon2id password hash, unique per (tenant, environment). This is a
--      minimal slice of the M7 password system: the same hash FORMAT, nothing
--      more (no tuning helper, no admission-controlled pool, no breach screening,
--      no lockout). The full model replaces it in M7.
--   2. sessions: the minimal server-side session behind the opaque, __Host-
--      prefixed session cookie. The cookie value IS the ses_ identifier, which
--      embeds its scope, so a session established in one (tenant, environment)
--      never resolves under another. auth_time records when the subject last
--      authenticated (the seam prompt/max_age semantics build on later). The real
--      two-tier session model with fleet operations is M4; this stays minimal and
--      self-contained.
--   3. consents: the recorded grant decision. A row means the subject has
--      authorized the client. The bootstrap records consent per (subject, client),
--      not per scope value: fine-grained per-scope consent is a later milestone.
--
-- The clients expand adds:
--   - token_endpoint_auth_method: the ONE method a client authenticates with at
--     the token endpoint (client_secret_basic, client_secret_post, or none for a
--     public PKCE-only client). Defaulting to 'none' keeps every client created
--     before this migration a public client, so the existing create path is
--     unchanged.
--   - secret_hash: the SHA-256 hash (hex) of a confidential client's generated
--     secret. The plaintext secret is shown once at creation and never stored, so
--     it is unrecoverable afterwards. A high-entropy (64 random byte) secret does
--     not need a slow password KDF; a single cryptographic hash is sound and is
--     what the management-key credential path already uses.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. All
-- three do so below.

-- ---------------------------------------------------------------------------
-- The bootstrap end-user directory.
--
-- identifier is the login handle the user types (for example an email or a
-- username); it is unique within a (tenant, environment) so registration rejects
-- a duplicate. password_hash is the Argon2id PHC string (algorithm, parameters,
-- salt, and hash), which is a one-way verifier: there is no column and no code
-- path that stores or recovers the plaintext password.
CREATE TABLE users (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The login handle, unique per scope.
    identifier     text        NOT NULL,
    -- The Argon2id PHC verifier string. One-way; never the plaintext.
    password_hash  text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One account per login handle per scope: registration relies on this to
    -- reject a duplicate identifier as a unique violation.
    UNIQUE (tenant_id, environment_id, identifier),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX users_scope_idx ON users (tenant_id, environment_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON users
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT: a bootstrap user is created and read back; no update or delete
-- path ships here (account lifecycle is M7).
GRANT SELECT, INSERT ON users TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The minimal server-side session.
--
-- The id is the ses_ session identifier, which is ALSO the opaque cookie value:
-- a scoped identifier that embeds its (tenant, environment) in the clear, so the
-- authorization endpoint recovers the scope from the presented cookie without a
-- database lookup, and a session established in one scope parses as a uniform
-- not-found under another. Its 128-bit unique component is cryptographically
-- random (from the entropy seam). subject is the authenticated end-user subject;
-- auth_time and expires_at both come from the application clock seam.
CREATE TABLE sessions (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The authenticated end-user subject (the tokens are minted for this).
    subject        text        NOT NULL,
    -- When the subject authenticated (the seam max_age/auth_time build on).
    auth_time      timestamptz NOT NULL,
    -- Session lifetime, from the application clock seam.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX sessions_scope_idx ON sessions (tenant_id, environment_id);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_tenant_isolation ON sessions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT: a session is created at login and read on later requests. The
-- M4 model owns revocation and rotation; this bootstrap enforces expiry by the
-- application clock at read time.
GRANT SELECT, INSERT ON sessions TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The recorded consent decision.
--
-- A row means the subject has authorized the client. Recorded per
-- (subject, client_id): once granted, a later authorization for the same client
-- skips the consent prompt. granted_scope keeps the scope value the decision was
-- made against for the audit trail; the bootstrap does not enforce per-scope
-- consent (that is a later milestone). The grant record (issue #12) references
-- the consent by its con_ id through the grant's consent_ref seam.
CREATE TABLE consents (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The authenticated subject and the client the decision is about.
    subject        text        NOT NULL,
    client_id      text        NOT NULL,
    -- The scope value the decision was made against (audit context only).
    granted_scope  text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT consents_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One recorded decision per (subject, client) per scope: a re-grant is an
    -- idempotent no-op rather than a second row.
    UNIQUE (tenant_id, environment_id, subject, client_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX consents_scope_idx ON consents (tenant_id, environment_id);

ALTER TABLE consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE consents FORCE ROW LEVEL SECURITY;
CREATE POLICY consents_tenant_isolation ON consents
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT: a consent is recorded once and read to skip the later prompt.
-- Revocation is a later milestone.
GRANT SELECT, INSERT ON consents TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Expand the existing clients table with secret-based client authentication.
--
-- Additive and safe for the old binary: the method defaults to 'none' (a public,
-- PKCE-only client), so every client created before this migration stays a public
-- client and the existing create path (which names neither column) is unchanged.
-- The secret_hash is the SHA-256 hex of a confidential client's generated secret;
-- the plaintext is shown once at creation and never stored, so it is
-- unrecoverable afterwards.
ALTER TABLE clients
    ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'none',
    ADD COLUMN secret_hash                text;
