-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per environment localization bundles (issue #86, PR 2).
--
-- The flow contract keys every human readable string on a STABLE NUMERIC message id plus a
-- structured context (see the flow message registry); the compiled English registry is the
-- ultimate fallback. Localization is therefore expressible ONLY as data that maps a numeric
-- id to a PLAIN TEXT string: a locale bundle is a map of numeric MessageId to a plain text
-- label, title, or error, rendered through the SAME HTML escaper the default text is. A
-- bundle string is never markup, never rich text, and never routed through the branding
-- sanitizer. This migration lands the one promotable per environment locale bundle row:
--
--   locale_bundles: one row per installed locale per environment. It holds:
--     - a scope embedded `lcb_` id (embeds its (tenant, environment), so a row minted in
--       one scope parses as a uniform not found under another);
--     - locale: the BCP47 language tag (for example `fr` or `fr-CA`), the stable per
--       environment natural key within scope (the promotion / diff key);
--     - entries: the serialized bundle (a jsonb object of numeric message id string to the
--       plain text render), validated at ingest so every key is a registered message id and
--       every interpolation placeholder is one the id declares. Never markup;
--     - is_env_default: whether this is the environment DEFAULT locale a scope resolves when
--       an end user requests no ui_locales the environment can render. At most one env
--       default per scope (a partial unique index enforces it, mirroring the brands default).
--
-- A locale bundle is PROMOTABLE (issue #41, classification.rs): the whole map is non secret
-- per environment config a config snapshot carries and a promotion replays. Per organization
-- localization is out of scope for #86.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and
-- FORCES row level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment locale bundle store (issue #86).
CREATE TABLE locale_bundles (
    -- The lcb_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The BCP47 language tag: the stable per environment natural key (the promotion / diff
    -- key). Unique per (tenant, environment).
    locale             text        NOT NULL,
    -- The serialized bundle: a jsonb object of numeric message id string to the plain text
    -- render. Validated at ingest (registered id, declared placeholders only). Never markup.
    entries            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- Whether this is the environment DEFAULT locale. At most one default per scope.
    is_env_default     boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT locale_bundles_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A locale tag is unique per (tenant, environment).
CREATE UNIQUE INDEX locale_bundles_locale_idx
    ON locale_bundles (tenant_id, environment_id, locale);
-- At most one ENV DEFAULT locale per (tenant, environment): the partial unique index is the
-- structural single default invariant (mirroring the brands default index).
CREATE UNIQUE INDEX locale_bundles_default_idx
    ON locale_bundles (tenant_id, environment_id)
    WHERE is_env_default;
-- The management list, the discovery ui_locales_supported read, and the config snapshot
-- export read a scope's locales ordered by (locale).
CREATE INDEX locale_bundles_scope_idx
    ON locale_bundles (tenant_id, environment_id, locale);

ALTER TABLE locale_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE locale_bundles FORCE ROW LEVEL SECURITY;
CREATE POLICY locale_bundles_tenant_isolation ON locale_bundles
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS the locale bundle lifecycle: set (create /
-- overwrite), get, and delete. It stores only already validated entries (the admin locales
-- path validates the registered ids and the declared placeholders before the write).
GRANT SELECT, INSERT, UPDATE, DELETE ON locale_bundles TO ironauth_control;
-- The DATA plane READS the installed locales on the render path (the resolved bundle for a
-- page) and the discovery ui_locales_supported read, so it holds SELECT only.
GRANT SELECT ON locale_bundles TO ironauth_app;
