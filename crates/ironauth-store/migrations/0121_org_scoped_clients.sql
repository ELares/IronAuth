-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Org-scoped clients (issue #103, bet 1, milestone M10).
--
-- An OAuth client owned by an ORGANIZATION rather than by the environment at large: the
-- capability every competitor tracks as an open issue and nobody ships (Keycloak #42781,
-- Zitadel #5219). This is the schema half; the behaviour rides behind the experimental
-- `org-scoped-clients` feature flag, default off, per the M1 maturity ladder.
--
--   1. NULLABLE, no default, and that is the whole upgrade-safety story. Every client
--      that exists today keeps `organization_id = NULL`, which means "owned by the
--      environment" and is exactly what those clients are. No row is rewritten and no
--      existing query changes meaning: a query that does not mention the column cannot
--      see it. A NOT NULL column would have required inventing an owner for every
--      client already in the field.
--
--   2. NULL is a MEANINGFUL value here, not an absence to be tidied away later. The
--      environment-owned client is the ordinary case and stays the default forever;
--      org-ownership is the opt-in. Reading NULL as "unassigned, fix later" would invert
--      that and make the common case look like debt.
--
--   3. No ON DELETE, so the foreign key is RESTRICT. CASCADE would delete a client
--      because its organization went away, and a deleted OAuth client is an outage for
--      whatever integrates with it: tokens stop minting and every deployed copy of that
--      integration breaks at once. Deleting an organization that still owns clients
--      should FAIL and make somebody decide, which is the same argument migration 0119
--      makes about confinement and 0120 about grants.
--
--   4. The index is PARTIAL over org-owned rows. Environment-owned clients are the vast
--      majority and are all NULL here, so indexing them would be a large index of one
--      value that answers no question anybody asks.
--
-- Migration safety obligation (see migrate.rs): `clients` is an EXISTING tenant-scoped
-- table that already ENABLEs and FORCEs row-level security and is already registered in
-- scripts/query-audit.sh, so this adds no new fencing obligation. The UPDATE grant is
-- COLUMN-scoped (the #31 lesson). Every statement is additive: this is an EXPAND.

ALTER TABLE clients
    ADD COLUMN organization_id text,
    ADD CONSTRAINT clients_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations (id);

-- "Which clients does this organization own": the read the org surface performs, and the
-- blast-radius answer before an organization is deleted.
CREATE INDEX clients_organization_idx
    ON clients (tenant_id, environment_id, organization_id)
    WHERE organization_id IS NOT NULL;

-- The CONTROL plane may assign ownership. `organization_id` joins the column-scoped
-- UPDATE list rather than replacing it: everything already grantable stays so.
--
-- Re-pointing a client at a DIFFERENT organization is deliberately permitted, unlike the
-- project-grant case in 0120, and the asymmetry is worth stating. A grant confers
-- authority, so silently moving one widens what somebody may do. Client ownership
-- confers no authority by itself; it decides which organization's surface manages the
-- client. Moving it is an administrative correction (a client created under the wrong
-- organization), and forbidding it would make that correction impossible without
-- deleting the client, which point 3 above establishes is an outage.
GRANT UPDATE (organization_id) ON clients TO ironauth_control;
