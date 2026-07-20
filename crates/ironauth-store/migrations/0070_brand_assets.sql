-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per environment brand assets and per domain / per client brand selection (issue #86, PR 3).
--
-- PR1 landed the promotable brand row with two RESERVED nullable columns (host_pattern,
-- client_id) for the selection seam, always NULL. This migration FILLS that seam and adds the
-- raster asset store:
--
--   brand_assets: the per brand binary chrome. One row per (scope, brand_slug, kind), kind in
--     a closed set ('logo' | 'favicon'). It holds:
--       - content_type: the SNIFFED media type (the magic byte sniff of the actual bytes, never
--         the client declared header), one of a small raster set. SVG is refused at ingest, so a
--         stored asset is never active markup;
--       - bytes: the raster payload, bounded by a size CHECK (a logo is capped well under the
--         hard 262144 byte ceiling the CHECK pins);
--       - sha256: the content digest the serve path turns into a strong ETag validator;
--       - size_bytes: the payload length in bytes (bounded by the same ceiling).
--     The natural key (scope, brand_slug, kind) is the PRIMARY KEY, so a brand has at most one
--     logo and at most one favicon. brand_slug references a brand's per environment natural key
--     within scope; existence is enforced at the management ingest (a clean 404 for an unknown
--     brand), not by a foreign key, since the brands slug uniqueness is a unique INDEX.
--
--   The two brands partial unique indexes (the routing confusion structural defense, mirroring
--   the #77 routing_rules): within a (tenant, environment) scope no two brands may claim the
--   same host_pattern, and no two may claim the same client_id. The columns already exist from
--   0068 (all NULL), so adding the partial unique indexes is additive and safe.
--
-- A brand asset is a sub part of the PROMOTABLE brand (issue #41, classification.rs): its
-- METADATA (kind, content_type, sha256, size_bytes) rides the BrandSnapshot by reference, and
-- the bytes travel on the deferred promotion apply, consistent with how the brand tokens/slots
-- and the locale bundle apply are already deferred. So brand_assets needs NO ResourceType of its
-- own (it is never independently exported); the snapshot resource set is UNCHANGED. Per
-- organization branding stays deferred to M10 and rides org export, never the snapshot.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and FORCES
-- row level security, adds the (tenant, environment) isolation policy, adds the nonempty scope
-- CHECK, and is registered in scripts/query-audit.sh. Every statement is additive, so this
-- migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The two brands selection partial unique indexes (issue #86, PR 3): the routing confusion
-- structural defense. Within a scope, a host_pattern and a client_id each select at most one
-- brand, so per domain / per client selection can never be ambiguous. Both predicates are
-- partial (WHERE ... IS NOT NULL), so the many NULL rows are unconstrained.
CREATE UNIQUE INDEX brands_host_pattern_idx
    ON brands (tenant_id, environment_id, host_pattern)
    WHERE host_pattern IS NOT NULL;
CREATE UNIQUE INDEX brands_client_id_idx
    ON brands (tenant_id, environment_id, client_id)
    WHERE client_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- The per environment brand asset store (issue #86, PR 3).
CREATE TABLE brand_assets (
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The brand's per environment natural key within scope (the brand this asset belongs to).
    brand_slug         text        NOT NULL,
    -- The asset kind: a closed set. One logo and one favicon per brand.
    kind               text        NOT NULL,
    -- The SNIFFED media type of the bytes (never the client declared header). Raster only.
    content_type       text        NOT NULL,
    -- The raster payload, bounded by the size CHECK below.
    bytes              bytea       NOT NULL,
    -- The content digest (lowercase hex sha256) the serve path turns into a strong ETag.
    sha256             text        NOT NULL,
    -- The payload length in bytes.
    size_bytes         integer     NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT brand_assets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed kind set: an unknown kind can never be written.
    CONSTRAINT brand_assets_kind_known
        CHECK (kind IN ('logo', 'favicon')),
    -- The hard size ceiling (262144 bytes): the bytes length and the recorded size_bytes are
    -- both bounded, so a management key holder cannot store an oversize payload that inflates the
    -- serve cost. The per kind caps (logo 256 KiB, favicon 64 KiB) are enforced at ingest.
    CONSTRAINT brand_assets_size_bounded
        CHECK (octet_length(bytes) <= 262144 AND size_bytes >= 0 AND size_bytes <= 262144),
    -- One logo and one favicon per brand per scope: the natural key is the PRIMARY KEY.
    CONSTRAINT brand_assets_pkey
        PRIMARY KEY (tenant_id, environment_id, brand_slug, kind),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The management list and the config snapshot metadata export read a scope's assets ordered by
-- (brand_slug, kind).
CREATE INDEX brand_assets_scope_idx
    ON brand_assets (tenant_id, environment_id, brand_slug, kind);

ALTER TABLE brand_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE brand_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY brand_assets_tenant_isolation ON brand_assets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) OWNS the asset lifecycle: upload / overwrite (the magic
-- byte sniffed, size capped, sudo gated PUT), delete, and the snapshot metadata read. It stores
-- only the sniffed content type and the validated bytes.
GRANT SELECT, INSERT, UPDATE, DELETE ON brand_assets TO ironauth_control;
-- The DATA plane READS an asset on the render / serve path (the same origin GET that streams the
-- stored bytes with server fixed headers), so it holds SELECT only.
GRANT SELECT ON brand_assets TO ironauth_app;
