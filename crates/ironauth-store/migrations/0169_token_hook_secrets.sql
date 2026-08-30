-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Which environment secrets a token hook may read. Issue #114 criterion 5, "per-hook secrets".
--
-- # A GRANT, never a value
--
-- Each row names an environment secret this hook is allowed to read. The VALUE stays in
-- `environment_secrets`, sealed, where the secret machinery already keeps it -- so this table
-- adds no second place a secret lives, no second thing to rotate, and no second thing a backup
-- of the wrong table would leak. A grant is a reference and a reference is not a secret.
--
-- That also makes revocation instant and total: deleting the row stops the next issuance from
-- resolving the value, with no re-deploy and no cache to invalidate, because the dispatch
-- resolves grants per invocation.
--
-- # No foreign key to the secret
--
-- Deliberately, and it is the one piece of referential integrity worth NOT having. A grant may
-- name a secret that does not exist yet: an operator arranging a hook before the secret is
-- provisioned, or promoting a configuration into an environment where the secret is created
-- separately, would otherwise be unable to express the arrangement at all. An unresolvable
-- grant is not an error state -- the hook reads `none` for that name, which is exactly what it
-- reads for a name it was never granted, and which its code has to handle either way.
--
-- The foreign key TO THE HOOK is present, and cascades, because the opposite is true there: a
-- grant to a hook that does not exist can never resolve to anything and is only ever litter.
-- Deleting a hook takes its grants with it, so redeploying a hook of the same name does not
-- silently inherit the permissions of the one it replaced.
--
-- # The name is the guest's key
--
-- A hook asks for a secret by NAME through `ironauth:hooks/secrets.get`, and the name it asks
-- for is the environment secret's name. There is no per-hook alias, deliberately: an alias is a
-- second name for one thing, and the failure it invites is an operator granting `stripe-key`
-- under the alias `key` to two hooks that mean different things by it.

CREATE TABLE token_hook_secrets (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    client_id       text        NOT NULL,
    hook_name       text        NOT NULL,
    secret_name     text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, environment_id, client_id, hook_name, secret_name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (tenant_id, environment_id, client_id, hook_name)
        REFERENCES token_hooks (tenant_id, environment_id, client_id, name)
        ON DELETE CASCADE,
    CONSTRAINT token_hook_secrets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT token_hook_secrets_client_nonempty
        CHECK (client_id <> ''),
    CONSTRAINT token_hook_secrets_secret_nonempty
        CHECK (secret_name <> '' AND secret_name = btrim(secret_name)
               AND length(secret_name) <= 128)
);

ALTER TABLE token_hook_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_hook_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY token_hook_secrets_scope ON token_hook_secrets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane READS grants on the issuance path and never writes one: the plane that mints
-- tokens must not be able to widen what the code shaping them may read. That is the same split
-- `token_hooks` itself draws, and for the stronger reason -- a write here is a grant of access
-- to a secret.
GRANT SELECT ON token_hook_secrets TO ironauth_app;
GRANT SELECT, INSERT, DELETE ON token_hook_secrets TO ironauth_control;
