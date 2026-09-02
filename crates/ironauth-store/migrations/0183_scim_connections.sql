-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0183: SCIM 2.0 inbound connections and their bearer tokens (issue #135, milestone M14).
--
-- An identity provider (Okta, Entra, anything speaking RFC 7644) provisions users and groups
-- into ONE organization of ONE environment. This table is the connection it authenticates as.
--
-- WHY THE TOKEN IS SCOPED TO EXACTLY ONE ORGANIZATION, in the schema rather than in a handler.
--
-- SCIM endpoints are a proven IDOR hot spot. Zitadel's CVE-2026-32130 was a SCIM auth bypass
-- through URL encoding, and Casdoor's CVE-2025-4210 was a SCIM authorization gap. The issue
-- asks that a token for org A be unusable against org B BY CONSTRUCTION, so the organization
-- is a NOT NULL column on the credential itself: there is no request shape in which a
-- connection names a second organization, because the connection has exactly one and the
-- caller never supplies it. A handler that forgot to compare would still be reading rows
-- through a scoped, org-filtered query.
--
--   1. THE PLAINTEXT TOKEN IS NEVER STORED. `token_digest` holds the SHA-256 of the whole
--      presented token and is the lookup key, exactly as `api_keys` (0123) and
--      `opaque_access_tokens` (0012) do it. The plaintext exists for the duration of the
--      creation response and nowhere else, which makes "shown once" a property of the schema
--      rather than a promise about a handler.
--
--   2. `id` is a NON-SECRET handle (an `scim_` scoped id). Every management operation, every
--      audit row and every provisioning event names this, never the digest and never the
--      token.
--
--   3. REVOKED ROWS ARE RETAINED, for the reason 0123 records: a deleted row makes a revoked
--      credential indistinguishable from one that never existed, and the audit rows naming it
--      outlive it either way.
--
--   4. `external_id_namespace` is per CONNECTION, not per environment. RFC 7643's `externalId`
--      is the IdP's own identifier and two IdPs provisioning into one organization can easily
--      use the same string for different people. Storing it against the connection is what
--      keeps "look this user up by the externalId my IdP knows" unambiguous; a per-environment
--      namespace would make the second connection's first provisioning either collide or
--      silently update the wrong person.
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
    -- The organization must exist. Organization ids are globally unique, so an id-only key is
    -- sufficient, exactly as `agents` (0176) and `org_memberships` do it. This is the backstop
    -- that makes a connection into a nonexistent or cross-scope organization impossible even
    -- though the handler resolves the organization up front.
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
GRANT SELECT, INSERT, UPDATE ON scim_connections TO ironauth_control;

-- The DATA plane READS, because every SCIM request authenticates against this table. It may
-- not write: a provisioning credential that could mint another provisioning credential would
-- be a privilege escalation with no operator in the loop.
GRANT SELECT ON scim_connections TO ironauth_app;

COMMENT ON TABLE scim_connections IS
    'Issue #135: one inbound SCIM connection, scoped to exactly ONE organization. The bearer '
    'token is stored only as a SHA-256 digest; the plaintext is returned once at creation and '
    'is recoverable from nothing.';
COMMENT ON COLUMN scim_connections.organization_id IS
    'Issue #135: THE boundary. A token for one organization is unusable against another by '
    'construction, because the organization is a property of the credential rather than a '
    'path parameter the caller supplies.';
COMMENT ON COLUMN scim_connections.token_digest IS
    'Issue #135: SHA-256 of the bearer token, never the token. A read of this table must not '
    'yield a credential that can provision an organization.';
