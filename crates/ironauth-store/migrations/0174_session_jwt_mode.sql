-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The OPT-IN short-lived JWT session mode. Issue #119, criterion 4.
--
-- > JWT session mode is opt-in: a fresh environment has it disabled, and enabling it requires
-- > an explicit setting.
--
-- # The absence of a row IS the default, and that is the whole design
--
-- A boolean column with `DEFAULT false` would also be off by default, and it would be a weaker
-- statement. A column exists on every environment, so "is this on" becomes a question about a
-- VALUE, and a value can be flipped by a migration, a backfill, a snapshot import, or a
-- well-meant `UPDATE ... SET enabled = true WHERE ...` that matched more rows than its author
-- expected. A row that does not exist cannot be flipped; it has to be INSERTED, by a caller
-- that names a template.
--
-- The issue asks for off "by default, forever". This is the shape that keeps that promise
-- without anyone having to remember it: a fresh environment has no row here, and there is no
-- code path that creates one except the management endpoint whose entire job is to.
--
-- # Why the setting is a TEMPLATE NAME and not a boolean
--
-- Turning this on means SDKs will mint short-lived JWTs against the session API in the
-- background. A JWT has to say who it is for and what it carries, and that is exactly what a
-- tokenizer template already is. A boolean would leave the audience, the TTL and the claim set
-- undefined, and something would have to invent defaults for all three -- which is how a
-- feature acquires an audience nobody chose.
--
-- So enabling the mode is NAMING A TEMPLATE, the foreign key makes that name real, and the
-- template's own TTL is the re-mint cadence and the revocation window. One number, configured
-- in one place, meaning the same thing on both surfaces.
--
-- ON DELETE CASCADE: deleting the template turns the mode OFF rather than leaving an
-- environment pointed at a template that no longer exists. That direction is the safe one --
-- the mode's failure mode is "SDKs fall back to the stateful check", which is where they would
-- end up anyway once the JWKS URL stopped answering.
--
-- Migration safety obligation (see migrate.rs): the new tenant-scoped table ENABLEs and FORCEs
-- row-level security, adds the (tenant, environment) isolation policy, adds the nonempty-scope
-- CHECK, declares the scope foreign keys directly, and is registered in scripts/query-audit.sh.
-- Every statement is additive, so this migration is an EXPAND.

CREATE TABLE session_jwt_mode (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The tokenizer template SDKs mint session JWTs from. Its TTL is the re-mint cadence and
    -- the revocation window.
    template_name   text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- ONE ROW PER ENVIRONMENT AT MOST. An environment cannot be in two session modes, and
    -- making that unrepresentable is better than a check somewhere that picks one.
    PRIMARY KEY (tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (tenant_id, environment_id, template_name)
        REFERENCES session_token_templates (tenant_id, environment_id, name) ON DELETE CASCADE,

    CONSTRAINT session_jwt_mode_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '')
);

ALTER TABLE session_jwt_mode ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_jwt_mode FORCE ROW LEVEL SECURITY;

CREATE POLICY session_jwt_mode_scope ON session_jwt_mode
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the switch. Enabling this changes how every SDK in the environment
-- checks whether a user is signed in, which is not a decision the plane serving logins gets to
-- make about itself.
GRANT SELECT, INSERT, UPDATE, DELETE ON session_jwt_mode TO ironauth_control;

-- And the DATA plane READS it, because the endpoint that tells an SDK which mode it is in is
-- served there. SELECT only.
GRANT SELECT ON session_jwt_mode TO ironauth_app;
