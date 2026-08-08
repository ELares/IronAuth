-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- A membership may bind a SERVICE ACCOUNT, not only a user (issue #99, criterion 3).
--
-- Criterion 3 asks that service accounts hold org-scoped roles and pass the same permission
-- checks as users. They cannot today: `org_memberships.user_id` is NOT NULL with a foreign
-- key to `users`, so a service account cannot hold a membership at all, and the whole role
-- and permission chain hangs off a membership row.
--
-- This is the SCHEMA and WRITE half. Resolution deliberately does NOT change here, and
-- `a_service_account_membership_does_not_yet_resolve_permissions` asserts exactly that. The
-- resolution change is `EFFECTIVE_CLOSURE_CTE`'s anchor and is about eight lines; it lands
-- separately so that diff can be reviewed and mutation-swept on its own, because it is the
-- query that decides which permissions a token carries.
--
--   1. `user_id` becomes NULLABLE. Relaxing a NOT NULL cannot fail on existing data and
--      cannot invalidate an existing row. Every membership that exists today keeps its user
--      and its foreign key.
--
--   2. `owner_kind` discriminates, defaulting to 'user'. The default is what makes this
--      migration a no-op for existing rows: they are all user memberships and they say so
--      without being rewritten.
--
--   3. The exclusive arc, as migration 0123 does for `api_keys`. A row that does not say
--      which kind of principal it binds cannot be resolved by either branch, and the
--      resolution anchor has to join a different table per kind.
--
--   4. NO new unique index for service accounts yet. The existing live-unique index is on
--      (organization, user) and stays exactly as it is; the service-account equivalent is
--      part of the resolution change, because whether two service-account memberships to one
--      organization are a conflict is a question the resolver answers, not the schema.
--
-- Migration safety obligation (see migrate.rs): `org_memberships` is an EXISTING
-- tenant-scoped table that already ENABLEs and FORCEs row-level security and is already
-- registered in scripts/query-audit.sh. The UPDATE grant is COLUMN-scoped (the #31 lesson).
-- Every statement is additive or a relaxation: this is an EXPAND.

ALTER TABLE org_memberships
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE org_memberships
    ADD COLUMN service_account_id text;

ALTER TABLE org_memberships
    ADD COLUMN owner_kind text NOT NULL DEFAULT 'user';

-- The closed vocabulary. NOT the thing that refuses an unknown kind: a mutation opening this
-- to `owner_kind IS NOT NULL` changed no observable behaviour, because the ARC below already
-- refuses anything that is neither branch. This stays because it DECLARES the closed set,
-- matching `permissions_kind_known`, and because it gives a caller a refusal naming the
-- column rather than the whole arc. The arc is the enforcement.
ALTER TABLE org_memberships
    ADD CONSTRAINT org_memberships_owner_kind_known
        CHECK (owner_kind IN ('user', 'service_account'));

-- The exclusive arc. Exactly the column named by `owner_kind` is populated.
ALTER TABLE org_memberships
    ADD CONSTRAINT org_memberships_owner_arc
        CHECK (
            (owner_kind = 'user'
                AND user_id IS NOT NULL
                AND service_account_id IS NULL)
            OR (owner_kind = 'service_account'
                AND service_account_id IS NOT NULL
                AND user_id IS NULL)
        );

ALTER TABLE org_memberships
    ADD CONSTRAINT org_memberships_service_account_fk
        FOREIGN KEY (service_account_id) REFERENCES service_accounts (id);

-- The sweep a service-account resolution will need, mirroring `org_memberships_user_idx`.
CREATE INDEX org_memberships_service_account_idx
    ON org_memberships (tenant_id, environment_id, service_account_id, created_at, id)
    WHERE service_account_id IS NOT NULL;

-- The data plane reads memberships on the authorization path and writes them on the
-- just-in-time provisioning path (issue #95), so it needs the new columns in both
-- directions. The control plane manages memberships through the admin surface.
GRANT UPDATE (service_account_id, owner_kind) ON org_memberships TO ironauth_app;
GRANT UPDATE (service_account_id, owner_kind) ON org_memberships TO ironauth_control;
