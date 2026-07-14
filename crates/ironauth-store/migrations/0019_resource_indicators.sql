-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- RFC 8707 Resource Indicators (issue #28).
--
-- Resource indicators let a client say WHICH resource server(s) a token is for,
-- so the issued access token's audience is restricted to exactly the requested
-- and allowlisted resources. This is the structural fix for cross-server token
-- replay and confused-deputy attacks, and it is mandatory for the MCP
-- authorization bundle (M13). This migration is ADDITIVE (every step is an expand:
-- a nullable ADD COLUMN, a CHECK that holds on the all-NULL new columns, and a
-- column-scoped grant): it introduces no new table, only new columns on existing
-- tenant-scoped tables (clients, grants, authorization_codes, opaque_access_tokens),
-- so all row-level security and isolation already in force on those tables applies
-- to the new columns unchanged.
--
-- clients: the per-client resource policy.
--   * allowed_resources           a JSON array of the resource URIs this client
--                                 may request. NULL means "no per-client allowlist
--                                 configured": the client may request ANY resource
--                                 that is a registered resource_server in its
--                                 environment (the environment-level resource_servers
--                                 registry is itself the allowlist). A non-NULL array
--                                 further RESTRICTS the client to its own entries.
--   * resource_indicator_policy   what to do when a request carries NO `resource`
--                                 parameter: 'default_audience' (the default; the
--                                 token's aud is the client id, preserving today's
--                                 no-resource behavior) or 'refuse' (a strict client
--                                 that must always name a resource: a no-resource
--                                 request fails invalid_target). NULL is read as
--                                 'default_audience'.
--
-- grants + authorization_codes: the GRANTED resource set, frozen at authorization
--   time (a JSON array of the approved resource audiences), so a refresh or a
--   later code exchange can DOWNSCOPE to a subset but can NEVER expand beyond the
--   original grant. It is frozen onto BOTH the grant (read by the refresh path
--   through the family -> grant join) and the code (read by the code-exchange path
--   through load_code), exactly as claims_request is frozen onto both. NULL / an
--   empty array means no resource was approved (the default-audience case).
--
-- opaque_access_tokens: the recorded audience array. An opaque token carries no
--   self-contained claims, so its audiences must be RECORDED here for the RFC 7662
--   introspection endpoint to report them accurately (a multi-resource token has an
--   aud ARRAY). The existing single `audience` column stays the primary audience
--   (backward compatible with every single-resource and no-resource token); the new
--   `audiences` column carries the full JSON array when it differs, and NULL falls
--   back to [audience].
--
-- Migration safety obligation (see migrate.rs): this migration adds NO new
-- tenant-scoped table, so there is no new ENABLE/FORCE row-level security, no new
-- isolation policy, and no new SCOPED_TABLES entry in scripts/query-audit.sh; the
-- columns inherit the isolation already forced on their tables. The one new
-- privilege is a COLUMN-SCOPED UPDATE grant on the two new clients columns (never a
-- table-wide UPDATE, per the issue #31 lesson).

ALTER TABLE clients ADD COLUMN allowed_resources text;
ALTER TABLE clients ADD COLUMN resource_indicator_policy text;

-- The no-resource policy is one of the two known values, or NULL (read as
-- 'default_audience'); an unknown value is a deliberate schema change.
ALTER TABLE clients ADD CONSTRAINT clients_resource_indicator_policy_valid
    CHECK (resource_indicator_policy IS NULL
           OR resource_indicator_policy IN ('default_audience', 'refuse'));

ALTER TABLE grants ADD COLUMN granted_resources text;
ALTER TABLE authorization_codes ADD COLUMN granted_resources text;

ALTER TABLE opaque_access_tokens ADD COLUMN audiences text;

-- Column-scoped UPDATE on ONLY the two new clients columns (issue #31 lesson:
-- never a table-wide UPDATE that would silently cover every future column). The
-- set-resource-indicator-policy management write updates exactly these two.
GRANT UPDATE (allowed_resources, resource_indicator_policy) ON clients TO ironauth_app;
