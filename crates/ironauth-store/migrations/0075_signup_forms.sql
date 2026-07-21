-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per environment, per client signup forms as data (issue #87, PR 1).
--
-- A signup form is a DECLARATIVE definition of which identity traits a signup (and a later
-- login progressive profiling step) collects, expressed as data rather than baked into the
-- flow: one row per (tenant, environment, client). It holds:
--
--   signup_forms: one row per (tenant, environment, client). It holds:
--     - a scope embedded `sgf_` id (embeds its (tenant, environment), so a row minted in one
--       scope parses as a uniform not found under another);
--     - client_id: the authorize client id this form governs, the stable per environment
--       natural key within scope (the promotion / diff key). Unique per (tenant, environment);
--     - fields: the serialized field list (a jsonb array), each field a trait pointer (RFC
--       6901), a required flag, an order, a step (signup or later_login), a narrowing only rule
--       object, and a label message id. Validated FAIL FAST at write time against the scope's
--       active trait schema (a field must name an existing, renderable trait, and every rule may
--       only TIGHTEN the trait's constraint), so the stored document is always already valid.
--       It carries NO secret and NO PII: only trait pointers, bounded rules, and numeric ids.
--
-- A signup form is PROMOTABLE (issue #41, classification.rs): the whole field list is non
-- secret per environment config a config snapshot carries and a promotion replays.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and
-- FORCES row level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment, per client signup form store (issue #87).
CREATE TABLE signup_forms (
    -- The sgf_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The authorize client id this form governs: the stable per environment natural key (the
    -- promotion / diff key). Unique per (tenant, environment).
    client_id          text        NOT NULL,
    -- The serialized field list: a jsonb array of field objects (trait pointer, required, order,
    -- step, narrowing only rules, label message id). Validated at write time against the active
    -- trait schema. Never a secret and never PII.
    fields             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signup_forms_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '' AND client_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A client id is unique per (tenant, environment): one signup form per (scope, client).
CREATE UNIQUE INDEX signup_forms_client_idx
    ON signup_forms (tenant_id, environment_id, client_id);

ALTER TABLE signup_forms ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_forms FORCE ROW LEVEL SECURITY;
CREATE POLICY signup_forms_tenant_isolation ON signup_forms
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS the signup form lifecycle: set (create /
-- overwrite), get, and delete. It stores only the fail fast validated field list (a nonexistent
-- or type incompatible trait, or a rule that widens the trait schema, is rejected before the
-- write).
GRANT SELECT, INSERT, UPDATE, DELETE ON signup_forms TO ironauth_control;
-- The DATA plane READS the active signup form on the flow creation path (PR 2 wires the schema
-- to node generation), so it holds SELECT only.
GRANT SELECT ON signup_forms TO ironauth_app;
