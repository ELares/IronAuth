-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per environment branding (issue #86, PR 1).
--
-- Safe branding is table stakes, but the obvious implementation is a stored XSS trap
-- (the Casdoor formCss / pageHtml class). The structural rule is that branding is
-- expressible ONLY through data that cannot become script: the design tokens are typed
-- scalars validated by the branding module before they reach this row, and the rich
-- text slots are allowlist sanitizer output. This migration lands the one promotable
-- per environment branding row:
--
--   brands: one row per named brand per environment. It holds:
--     - a scope embedded `brd_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - slug: the stable, human readable per environment natural key (the promotion /
--       diff key);
--     - is_default: whether this is the environment DEFAULT brand a scope resolves when
--       nothing more specific is selected. At most one default per scope (a partial
--       unique index enforces it). Per domain / per client selection is deferred to PR3;
--     - product_name / show_wordmark / brand_token: the plain text wordmark fields
--       (escaped on render, never markup);
--     - tokens / tokens_dark: the serialized TYPED design tokens (a jsonb object of
--       validated scalars: hex only colors, an allowlist font enum, clamped numerics),
--       the light and optional dark mode variants. Never free form CSS;
--     - slots: the serialized sanitized rich text slots (a jsonb object of slot key to
--       allowlist sanitized markup). Never raw HTML at any layer;
--     - host_pattern / client_id: RESERVED nullable columns for the PR3 per domain /
--       per client selection seam. Unused in PR1 (always NULL), so PR3 is an additive
--       fill, not a schema change.
--
-- A brand is PROMOTABLE (issue #41, classification.rs): the whole definition is non
-- secret per environment config a config snapshot carries and a promotion replays. Per
-- organization branding is deferred to M10 and rides org export, never the snapshot.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and
-- FORCES row level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment branding store (issue #86).
CREATE TABLE brands (
    -- The brd_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The stable, human readable per environment brand slug (the promotion / diff key).
    slug               text        NOT NULL,
    -- Whether this is the environment DEFAULT brand. At most one default per scope.
    is_default         boolean     NOT NULL DEFAULT false,
    -- The plain text product name / wordmark (escaped on render, never markup).
    product_name       text        NOT NULL,
    -- Whether to show the wordmark header.
    show_wordmark      boolean     NOT NULL DEFAULT true,
    -- The optional plain text brand token badge (escaped on render), or NULL.
    brand_token        text,
    -- The serialized TYPED design tokens (validated scalars). Never free form CSS.
    tokens             jsonb       NOT NULL,
    -- The serialized dark mode token variants, or NULL (dark mode reuses the neutral
    -- built in block).
    tokens_dark        jsonb,
    -- The serialized sanitized rich text slots (slot key -> allowlist sanitized markup).
    slots              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- RESERVED nullable selection seam for PR3 (per domain / per client). Unused in PR1.
    host_pattern       text,
    client_id          text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT brands_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A brand slug is unique per (tenant, environment).
CREATE UNIQUE INDEX brands_slug_idx
    ON brands (tenant_id, environment_id, slug);
-- At most one DEFAULT brand per (tenant, environment): the partial unique index is the
-- structural single default invariant.
CREATE UNIQUE INDEX brands_default_idx
    ON brands (tenant_id, environment_id)
    WHERE is_default;
-- The management list and the config snapshot export read a scope's brands ordered by
-- (created_at, id).
CREATE INDEX brands_scope_idx
    ON brands (tenant_id, environment_id, created_at, id);

ALTER TABLE brands ENABLE ROW LEVEL SECURITY;
ALTER TABLE brands FORCE ROW LEVEL SECURITY;
CREATE POLICY brands_tenant_isolation ON brands
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS the brand lifecycle: create / overwrite,
-- list / get, and delete. It stores only already validated tokens and already sanitized
-- slots (the branding module validates and sanitizes before the write).
GRANT SELECT, INSERT, UPDATE, DELETE ON brands TO ironauth_control;
-- The DATA plane READS the resolved brand on the render path (the served stylesheet and
-- the flow page), so it holds SELECT only.
GRANT SELECT ON brands TO ironauth_app;
