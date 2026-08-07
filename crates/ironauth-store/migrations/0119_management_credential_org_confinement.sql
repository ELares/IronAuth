-- Confine a management credential to ONE organization (issue #102, delegated administration).
--
-- Migration 0118 gave a credential a permission set: WHAT it may do. This gives it an optional
-- organization: WHERE it may do it. The two are independent dimensions and both are needed,
-- because #102's org-admin persona is defined by holding organizational permissions AND being
-- unable to reach any organization but its own. A permission set alone cannot express that: a
-- credential granted `management.write_organizations` today may write EVERY organization in
-- the environment.
--
-- NULL means NOT CONFINED, which is every credential that exists when this runs and is the
-- same expand-only shape 0118 used. A confinement nobody wrote cannot take reach away, so no
-- deployment loses anything at upgrade. A default would revoke every key's reach in every
-- deployment, which is an outage rather than a security improvement.
--
-- The foreign key is single column, to `organizations (id)`, which is the convention every
-- other organization reference in this schema uses (0085, 0086). A composite
-- `(organization_id, tenant_id)` was the first attempt and is UNWRITABLE: `organizations` has
-- no unique constraint on `(id, tenant_id)`, so Postgres refuses the constraint outright
-- ("there is no unique constraint matching given keys"). Cross-tenant confinement is instead
-- prevented the way it is everywhere else here: an `org_` id embeds its own scope, so a
-- foreign-tenant id fails to parse in scope before any statement runs.
--
-- ON DELETE is deliberately absent, so the default RESTRICT applies. A confined credential
-- blocks deletion of the organization it is confined to, and that is the behaviour worth
-- having: a CASCADE would silently widen the credential from "this org only" to "every org in
-- the environment" at the moment its organization was removed, which is the exact opposite of
-- what an operator confining a credential asked for. Failing the delete is loud and
-- recoverable; silently escalating a credential is neither.
--
-- Expand-only and safe for the old binary: one nullable column and its index. A binary that
-- predates this migration never reads or writes it, and because NULL is unconfined it behaves
-- exactly as before.

ALTER TABLE management_credentials
    ADD COLUMN organization_id text,
    ADD CONSTRAINT management_credentials_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations (id);

-- The lookup is by credential id, which is already the primary key, so this index exists for
-- the REVERSE question an operator asks at offboarding: which credentials are confined to this
-- organization. Partial, because unconfined credentials are the overwhelming majority and none
-- of them is an answer to that question.
CREATE INDEX management_credentials_organization_idx
    ON management_credentials (tenant_id, environment_id, organization_id)
    WHERE organization_id IS NOT NULL;

-- The control plane owns the credential lifecycle, so it owns the confinement. Column scoped
-- per the #31 lesson, never a table-wide UPDATE.
GRANT UPDATE (organization_id) ON management_credentials TO ironauth_control;
