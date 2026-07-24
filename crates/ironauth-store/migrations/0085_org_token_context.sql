-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The durable organization token context (issue #94, PR-B1).
--
-- PR-A landed the organization data model (organizations.state, org_memberships,
-- and the data-plane SELECT on both). This migration threads a DURABLE org context
-- along the existing authentication relay so a token can carry an org_id claim:
--
--   login flow -> the session row (org_id) -> /authorize freezes it onto the auth
--   grant -> the token endpoint reads it back -> the org_id claim.
--
-- It mirrors exactly how the authenticating session (session_ref) already freezes
-- onto the grant. The org context is resolved ONCE per session and frozen (first
-- write wins), so every code issued from a session, and every token minted from
-- those codes, carries the SAME org_id. Two additive nullable columns and one new
-- column grant; RLS, the isolation policies, and every existing grant are untouched.
--
--   1. sessions.org_id (nullable). The per-session frozen org context. Written once,
--      at the first /authorize that resolves an org for the session, through a first
--      write wins UPDATE guarded on org_id IS NULL, so a later conflicting
--      organization parameter can never re-bind an already-bound session. The data
--      plane needs a COLUMN-scoped UPDATE of exactly this column to write it.
--   2. grants.org_id (nullable). The org context frozen onto the authorization grant
--      at code issuance, read back at the token endpoint (the code exchange) and by
--      the refresh path, exactly as session_ref is. The data plane already holds a
--      table-wide SELECT, INSERT, UPDATE on grants (migration 0004), which covers the
--      new column, so no grant is added here.
--
-- Both columns reference organizations(id): the organization id is globally unique
-- (a text primary key embedding its own scope), so an id-only foreign key is the
-- referential backstop, the same shape org_memberships uses. A disabled or
-- soft-deleted organization still satisfies the key (the row exists); the login
-- path enforces membership and the active state authoritatively before it ever
-- writes org_id, never the database.
--
-- Migration safety obligation (see migrate.rs): this migration adds NO table, so it
-- ENABLEs no new row-level security and registers no new table in query-audit.sh.
-- Every statement is additive (a nullable column, an id-only foreign key, one column
-- grant), safe for the old binary to ignore, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The per-session frozen org context (issue #94, PR-B1).
--
-- Nullable: a session with no resolved org (a member-less user, or a multi-org user
-- who named no organization) carries NULL and its tokens carry no org_id claim, so
-- a login unaffected by orgs is byte-identical to before this migration.
ALTER TABLE sessions
    ADD COLUMN org_id text;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_org_fk
    FOREIGN KEY (org_id) REFERENCES organizations (id);

-- The data plane freezes the org context onto the session with a first write wins
-- UPDATE (SET org_id WHERE org_id IS NULL) at the first /authorize that resolves an
-- org. Least privilege: a COLUMN-scoped UPDATE of EXACTLY org_id, never a table-wide
-- UPDATE (the #31 lesson). SELECT is already granted table-wide on sessions to the
-- data plane (migration 0006), which covers reading the frozen value back.
GRANT UPDATE (org_id) ON sessions TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The org context frozen onto the authorization grant (issue #94, PR-B1).
--
-- The grant is the revocation spine that already carries the authenticating
-- session_ref; org_id rides alongside it. It is written at code issuance (the grant
-- INSERT) and read back at the token endpoint (a JOIN from the code to its grant)
-- and on the refresh path (the family's grant), so a refreshed access token keeps
-- the same org_id. No grant is added: the data plane already holds table-wide
-- SELECT, INSERT, UPDATE on grants (migration 0004), which covers this column.
ALTER TABLE grants
    ADD COLUMN org_id text;
ALTER TABLE grants
    ADD CONSTRAINT grants_org_fk
    FOREIGN KEY (org_id) REFERENCES organizations (id);
