-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- A tenant's CUSTOM FACTOR components. Issue #114 criterion 6.
--
-- # Why this is not a row in `token_hooks`
--
-- A token hook and a challenge component are both WASM, deployed the same way, bounded the same
-- way. Everything else about them differs, and the differences are all in the KEY.
--
-- A token hook is deployed AGAINST A CLIENT: its identity is (scope, client, name), it has an
-- ordinal because a client's hooks run as an ordered chain, and `MAX_HOOKS_PER_CLIENT` bounds
-- how many of them one login can be made to run. A challenge component is deployed against the
-- ENVIRONMENT and referenced BY NAME from a journey step: no client, no ordinal, and the bound
-- that matters is on how many steps a journey has, which the journey validator already owns.
--
-- Putting them in one table would mean every existing read of `token_hooks` grows a filter it
-- did not have -- `chain` would return components that export the wrong world and fail to
-- instantiate on the issuance path, which is the worst place to discover it -- and the ordinal
-- UNIQUE constraint would have to admit rows that have no position. The cost of a second table
-- is the version history and rollback machinery, and this change does not ship those: a custom
-- factor is redeployed by name, and rollback arrives with the surface that needs it rather than
-- being built for nobody.
--
-- # The name is the journey's reference
--
-- A journey step names the component it runs. That makes the name part of a CONFIGURATION
-- CONTRACT rather than a label: renaming a component breaks every journey that referenced it,
-- exactly as renaming a subflow would. The name is bounded and non-empty here so that contract
-- has a shape the database enforces, and the admin surface refuses one that does not fit rather
-- than surfacing a constraint violation.

CREATE TABLE challenge_components (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The name a journey step references this component by.
    name            text        NOT NULL,
    -- The WASM component, as bytes. Exports `custom-challenge`, which is checked where it is
    -- loaded rather than here: this table stores bytes and cannot parse a component.
    component       bytea       NOT NULL,
    -- The payload version the guest was built against, for the same reason `token_hooks` stores
    -- one: a component compiled against version 1 and invoked with a version 2 context reads
    -- fields that moved, and the only way to refuse that is to know what it expected.
    payload_version integer     NOT NULL,
    -- How many outbound requests ONE call of the triad may make, granted per component exactly
    -- as it is for a token hook. Zero is the default and means NOT GRANTED.
    --
    -- PER CALL, not per factor: the triad is three separate invocations, each with its own
    -- sandbox, so each gets this budget. A factor that checks an answer against an upstream
    -- needs it in `verify` and not in `define`, and a budget that were shared across the three
    -- would make `define` able to starve `verify`.
    fetch_budget    integer     NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),

    CONSTRAINT challenge_components_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- BOUNDED AND NON-EMPTY, because the name is a journey's reference to this row. Sixty-four
    -- characters matches the token hook name bound, so an operator learns one rule rather than
    -- two.
    CONSTRAINT challenge_components_name_bounded
        CHECK (name <> '' AND length(name) <= 64),
    -- SIXTEEN MEBIBYTES, matching what 0166 RAISED the token-hook bound to, and the reason is
    -- the reason 0166 gives rather than a number copied across.
    --
    -- A factor compiled from Rust is tens of kilobytes. A factor written in a scripting language
    -- carries its interpreter: the TypeScript component this repository ships is roughly 10.6
    -- MiB, of which the author's own code is about four kilobytes. An eight-megabyte bound would
    -- not squeeze TypeScript factors, it would make every one of them undeployable through this
    -- product's own admin surface while the integration suite ran them happily -- because a
    -- suite loads a component from disk and never crosses this constraint.
    --
    -- The first draft of this migration carried 8 MiB, copied from 0162 without noticing 0166
    -- had already moved it. `every_component_bound_admits_the_shipped_typescript_hook` is what
    -- caught that, which is exactly the job of a gate that reads every bound in the schema
    -- rather than the one a change happened to touch.
    --
    -- Bounded at all because this column is read on the LOGIN path: an unbounded one is an
    -- unbounded read on every login that reaches the step.
    CONSTRAINT challenge_components_component_bounded
        CHECK (octet_length(component) > 0 AND octet_length(component) <= 16777216),
    CONSTRAINT challenge_components_payload_version_known
        CHECK (payload_version = 1),
    -- The same sixteen-request ceiling `token_hooks` carries. A fetch is the one host call a
    -- component makes that can BLOCK, and none of fuel, the memory cap or the epoch deadline
    -- sees time spent inside one, so the worst case is this number times the transport timeout.
    CONSTRAINT challenge_components_fetch_budget_bounded
        CHECK (fetch_budget >= 0 AND fetch_budget <= 16)
);

ALTER TABLE challenge_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenge_components FORCE ROW LEVEL SECURITY;

CREATE POLICY challenge_components_scope ON challenge_components
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle: deploying a component is deploying CODE that decides
-- whether a login succeeds.
--
-- DELETE is granted here, unlike 0162 which withheld it until the removal surface existed. The
-- difference is that this change ships that surface: a privilege held by nobody is one an
-- attacker inherits for free, and a privilege the shipped code needs is one withholding would
-- only break.
GRANT SELECT, INSERT, UPDATE, DELETE ON challenge_components TO ironauth_control;

-- And the DATA plane READS it, because the login path is what runs the factor. SELECT only: the
-- plane that runs a component must never be the plane that can change one.
GRANT SELECT ON challenge_components TO ironauth_app;

-- The GRANTED SECRETS a challenge component may read, by name.
--
-- The same shape `token_hook_secrets` has and for the same reasons: a GRANT, never a value. The
-- values live in the environment secret store; this table says which names this component is
-- allowed to ask for, and the host resolves them before the guest runs.
CREATE TABLE challenge_component_secrets (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The component this grant is for.
    name            text        NOT NULL,
    -- The environment secret name this component may read.
    secret_name     text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, name, secret_name),
    -- CASCADE, so deleting a component takes its grants with it. A grant that outlived its
    -- component would be re-attached silently by a later deploy of the same name, which is a
    -- capability nobody granted.
    FOREIGN KEY (tenant_id, environment_id, name)
        REFERENCES challenge_components (tenant_id, environment_id, name) ON DELETE CASCADE,

    -- NO FOREIGN KEY TO THE SECRET, deliberately, matching `token_hook_secrets`: an operator may
    -- grant a name before the secret exists, and the host answers `none` for a name with no
    -- value. Requiring the secret first would force an ordering on two independent operations.
    CONSTRAINT challenge_component_secrets_name_bounded
        CHECK (secret_name <> '' AND length(secret_name) <= 128)
);

ALTER TABLE challenge_component_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenge_component_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY challenge_component_secrets_scope ON challenge_component_secrets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT ON challenge_component_secrets TO ironauth_app;
GRANT SELECT, INSERT, DELETE ON challenge_component_secrets TO ironauth_control;
