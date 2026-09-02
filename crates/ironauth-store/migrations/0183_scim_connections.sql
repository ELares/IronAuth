-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0183: SCIM 2.0 inbound connections and their bearer tokens (issue #135, milestone M14).
--
-- An identity provider (Okta, Entra, anything speaking RFC 7644) provisions users and groups
-- into ONE organization of ONE environment. This table is the connection it authenticates as.
--
-- WHY THE TOKEN IS SCOPED TO EXACTLY ONE ORGANIZATION, in the schema rather than in a handler.
--
-- SCIM endpoints are a proven AUTHORIZATION hot spot, and the two shipped CVEs on this
-- surface are both failures of the authenticate step rather than of the compare step:
-- Zitadel's CVE-2026-32130 was an authentication BYPASS through URL encoding (CWE-288), and
-- Casdoor's CVE-2025-4210 was a MISSING authorization check (CWE-285) on a route that
-- consulted no credential at all. Neither is an IDOR, and this column does not fix either
-- of them: a route that never authenticates has no credential for an organization to be
-- bound to.
--
-- What this column does is remove the step where such a bug becomes cross-tenant. The issue
-- asks that a token for org A be unusable against org B BY CONSTRUCTION, so the organization
-- is a NOT NULL column on the credential itself: there is no request shape in which a
-- connection names a second organization, because the connection has exactly one and the
-- caller never supplies it. A handler that forgot to compare would still be reading rows
-- through a scoped, org-filtered query. That is a precondition for the authenticated path
-- being safe, not a defence against an unauthenticated one.
--
--   1. THE PLAINTEXT TOKEN IS NEVER STORED. `token_digest` holds the SHA-256 of the whole
--      presented token and is the lookup key, exactly as `api_keys` (0123) and
--      `opaque_access_tokens` (0012) do it.
--
--      What the schema establishes is NARROWER than "shown once", and worth stating exactly:
--      the digest is the only stored form, so no read of this table can yield a usable
--      credential. Whether a handler returns the plaintext once, twice, or writes it to a log
--      is a property of that handler, and no such handler exists yet.
--
--   2. `id` is a NON-SECRET handle (an `scim_` scoped id). Every management operation, every
--      audit row and every provisioning event names this, never the digest and never the
--      token.
--
--   3. REVOKED ROWS ARE RETAINED, for the reason 0123 records: a deleted row makes a revoked
--      credential indistinguishable from one that never existed, and the audit rows naming it
--      outlive it either way.
--
--   4. THE ORGANIZATION IS A TYPED, SCOPE-CHECKED ID on the write path, not just a column.
--      The foreign key below is id-only, and Postgres referential integrity checks BYPASS row
--      level security, so a bare string resolved any globally existing organization -- another
--      tenant's included. The repository takes an `OrganizationId` and refuses one out of
--      scope; this key is the backstop for a NONEXISTENT organization, and only that.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it
-- inert.

CREATE TABLE scim_connections (
    -- The SHA-256 hex digest of the whole presented bearer token. The verification lookup key.
    token_digest         text        PRIMARY KEY,
    -- The non-secret handle every management operation and audit row names.
    id                   text        NOT NULL UNIQUE,
    tenant_id            text        NOT NULL,
    environment_id       text        NOT NULL,
    -- THE boundary. One organization, named here and never by the caller.
    organization_id      text        NOT NULL,
    -- The operator-facing label ("Okta production", "Entra staging").
    display_name         text        NOT NULL,
    -- Which IdP this connection is for, so an operator reading a provisioning trail can tell
    -- two connections apart by more than their labels. A closed vocabulary: an unknown IdP is
    -- `generic`, which is honest, rather than a free string that becomes a de facto enum.
    provider             text        NOT NULL DEFAULT 'generic',
    -- Optional expiry, from the APPLICATION clock, so a manual test clock resolves it
    -- deterministically. See 0182 for what mixing the two clocks costs.
    expires_at           timestamptz,
    revoked_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_connections_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scim_connections_display_name_nonempty
        CHECK (display_name <> ''),
    -- 64 lowercase hex characters. A shorter value is a truncated digest, and a truncated
    -- digest compares equal more often than it should.
    CONSTRAINT scim_connections_digest_shaped
        CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT scim_connections_provider_known
        CHECK (provider IN ('okta', 'entra', 'generic')),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization must EXIST. That is all this key does, and the distinction matters
    -- enough to spell out: referential integrity checks BYPASS row-level security, so an
    -- id-only key admits any globally existing organization, another tenant's included. What
    -- refuses a cross-scope one is the repository, which takes a scope-checked
    -- `OrganizationId`. A composite key would say it here too, but `organizations` carries no
    -- `UNIQUE (id, tenant_id, environment_id)` to reference.
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The management listing: every connection for one organization, oldest first.
CREATE INDEX scim_connections_by_org
    ON scim_connections (tenant_id, environment_id, organization_id, created_at, id);

-- Resolve a connection by its non-secret handle, for revoke and rotate. Scoped first, as every
-- index here is.
CREATE UNIQUE INDEX scim_connections_by_id
    ON scim_connections (tenant_id, environment_id, id);

ALTER TABLE scim_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_connections_scope ON scim_connections
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle: creating a connection mints a credential that can
-- write users and groups into an organization, which is squarely an operator action.
--
-- UPDATE IS COLUMN SCOPED, exactly as 0123 scopes it for `api_keys`. A whole-table UPDATE let
-- the control role re-point `organization_id` at another organization, swap `token_digest` for
-- one it chose, or set `revoked_at` back to NULL -- so the boundary this table exists to
-- enforce, the verifier, and the permanence of revocation were all editable by the role that
-- creates connections. Only revocation is a legitimate update.
GRANT SELECT, INSERT ON scim_connections TO ironauth_control;
GRANT UPDATE (revoked_at, updated_at) ON scim_connections TO ironauth_control;

-- And revocation is ONE WAY. The column grant above stops a re-pointing; this stops an
-- un-revocation, which the grant cannot express because `revoked_at` is exactly the column a
-- revoke must write.
--
-- AS RESTRICTIVE, deliberately: `scim_connections_scope` has no FOR clause and no TO clause,
-- so a permissive narrowing would be OR'd with a check the offending update already satisfies
-- and would constrain nothing. 0181 and 0182 record the same reasoning.
CREATE POLICY scim_connections_revoke_is_one_way
    ON scim_connections
    AS RESTRICTIVE
    FOR UPDATE
    TO ironauth_control
    USING (revoked_at IS NULL)
    WITH CHECK (revoked_at IS NOT NULL);

-- The DATA plane READS, because every SCIM request authenticates against this table. It may
-- not write: a provisioning credential that could mint another provisioning credential would
-- be a privilege escalation with no operator in the loop.
GRANT SELECT ON scim_connections TO ironauth_app;

COMMENT ON TABLE scim_connections IS
    'Issue #135: one inbound SCIM connection, scoped to exactly ONE organization. The bearer '
    'token is stored only as a SHA-256 digest, so no read of this table yields a usable '
    'credential.';
COMMENT ON COLUMN scim_connections.organization_id IS
    'Issue #135: THE boundary. A token for one organization is unusable against another by '
    'construction, because the organization is a property of the credential rather than a '
    'path parameter the caller supplies.';
COMMENT ON COLUMN scim_connections.token_digest IS
    'Issue #135: SHA-256 of the bearer token, never the token. A read of this table must not '
    'yield a credential that can provision an organization.';
