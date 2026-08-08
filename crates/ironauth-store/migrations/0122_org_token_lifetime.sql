-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-organization ACCESS TOKEN lifetime (issue #103, bet 1, milestone M10).
--
-- Migration 0090 gave an organization a session lifetime; this gives it a token
-- lifetime, which is a different thing and the one acceptance criterion 1 actually needs.
--
-- Why the two are separate, since "token and session lifetime overrides" reads like one
-- feature. A SESSION belongs to the user's authentication and is client-agnostic:
-- `establish_session` takes no client, and `sessions` carries no `client_id`, so the same
-- session serves every application the user visits. An ACCESS TOKEN is issued TO a
-- specific client. So a per-organization override attached to a CLIENT'S owner is
-- expressible on the token and not on the session: applying one to the session would give
-- a user a different session lifetime depending on which application they signed in
-- through, and would silently re-time a session they already hold when they visit another.
--
--   1. NULLABLE, no default. An organization that states nothing keeps the deployment's
--      configured token lifetime, which is what every organization does today. No row is
--      rewritten and no resolution changes for anybody who does not opt in.
--
--   2. The CHECK mirrors `org_auth_policies_session_ttl_positive` exactly. Zero is
--      refused because a zero-second token is not a short token, it is a token that is
--      expired at issue: every request carrying it fails, and the failure looks like a
--      clock problem rather than a policy one.
--
--   3. This does NOT replace `resource_servers.access_token_ttl_secs` (migration 0011).
--      That is a per-RESOURCE-SERVER axis: how long a token FOR THAT API stays valid.
--      This is per-ORGANIZATION: how long a token issued through that organization's
--      client stays valid. They compose by narrowing, so the shorter wins and neither can
--      be used to lengthen past the other.
--
-- Migration safety obligation (see migrate.rs): `org_auth_policies` is an EXISTING
-- tenant-scoped table that already ENABLEs and FORCEs row-level security and is already
-- registered in scripts/query-audit.sh. The UPDATE grant is COLUMN-scoped (the #31
-- lesson) and joins the existing list rather than replacing it. Every statement is
-- additive: this is an EXPAND.

ALTER TABLE org_auth_policies
    ADD COLUMN access_token_ttl_secs integer;

ALTER TABLE org_auth_policies
    ADD CONSTRAINT org_auth_policies_access_token_ttl_positive
        CHECK (access_token_ttl_secs IS NULL OR access_token_ttl_secs > 0);

-- The control plane may state the override. The data plane keeps SELECT only, granted by
-- 0090 on the whole row, for the same reason recorded there: the resolution engine runs
-- on the authorization path under the low-privilege app role, and a data plane able to
-- rewrite its own token lifetime is the threat that grant split exists to prevent.
GRANT UPDATE (access_token_ttl_secs) ON org_auth_policies TO ironauth_control;
