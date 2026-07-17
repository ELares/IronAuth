-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Declarative inbound-federation connectors (issue #75, PR A).
--
-- Every identity provider faces the same fork: absorb the provider long tail as
-- in-tree code, or make it configuration. This migration lands the DATA plane of
-- the second path: one tenant-scoped table holding declarative OIDC-shaped upstream
-- connector definitions, so adding a provider is a definition rather than in-tree
-- code and a release. The definition itself (issuer or explicit endpoints, scopes,
-- client id, PKCE mode, claim mapping, quirks, and the capability matrix) is parsed
-- and strictly validated by the pure ironauth-connector crate BEFORE it reaches
-- this table.
--
--   connectors: one row per connector definition per environment. It holds:
--     - a scope-embedded `cnr_` id (embeds its (tenant, environment), so a connector
--       minted in one scope parses as a uniform not-found under another; the prefix
--       is `cnr`, distinct from consent's `con`);
--     - connector_slug: the stable, human-readable per-environment identifier, unique
--       per (tenant, environment);
--     - definition_json: the SECRET-FREE projection of the connector definition (the
--       upstream client_secret field is stripped before storage), so a database dump
--       or a config snapshot of this column carries no secret material even in
--       principle;
--     - client_secret_sealed / client_secret_dek_version: the upstream client secret,
--       SEALED under the scope's envelope DEK (issue #48), never a plaintext column.
--       It is sealed INLINE on this row (like the admin user-PII path), NOT as a row
--       in the shared encrypted_secrets store: the management API seals it on the
--       CONTROL-plane role, which is granted the KEK/DEK provisioning it needs (issue
--       #37) but is deliberately NOT granted the shared encrypted_secrets store (that
--       would let the control plane read every scope's TOTP seeds and other secrets).
--       Inline sealing confines the control plane's secret access to the connector
--       rows it owns, RLS-scoped, while the value stays envelope-encrypted at rest;
--     - cap_refresh / cap_groups / cap_logout_propagation / cap_email_verified_trust:
--       the machine-readable capability matrix, WRITTEN FROM the definition at write
--       time (single source of truth = the definition). email_verified_trust defaults
--       conservatively to 'untrusted': a connector's assertion that an email is
--       verified is not believed unless the definition explicitly raises the trust;
--     - enabled: whether the connector is active;
--     - created_at / updated_at.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table ENABLES
-- and FORCES row-level security, adds the (tenant, environment) isolation policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per-environment declarative federation connector registry (issue #75).
--
-- id is a `cnr_` scoped identifier (embeds its (tenant, environment)), so a connector
-- minted in one scope parses as a uniform not-found under another. connector_slug is
-- the stable per-environment natural key (a config snapshot orders by it).
-- definition_json is the secret-free definition. client_secret_sealed is the upstream
-- client secret sealed under the scope's active DEK (issue #48); client_secret_dek_version
-- records the DEK version. The cap_* columns are the capability matrix written from the
-- definition.
CREATE TABLE connectors (
    id                          text        PRIMARY KEY,
    tenant_id                   text        NOT NULL,
    environment_id              text        NOT NULL,
    -- The stable, human-readable per-environment connector identifier.
    connector_slug              text        NOT NULL,
    -- The SECRET-FREE projection of the connector definition (the upstream
    -- client_secret field is stripped before storage). Never carries secret material.
    definition_json             jsonb       NOT NULL,
    -- The upstream client secret, sealed under the scope's DEK (issue #48). Never a
    -- plaintext column, never in definition_json, never in a config snapshot.
    client_secret_sealed        bytea       NOT NULL,
    -- The DEK version the client secret was sealed under.
    client_secret_dek_version   integer     NOT NULL,
    -- The capability matrix, written FROM the definition at write time (single source
    -- of truth = the definition).
    cap_refresh                 boolean     NOT NULL,
    cap_groups                  boolean     NOT NULL,
    cap_logout_propagation      boolean     NOT NULL,
    -- How much the upstream's email_verified claim is trusted (a closed set); defaults
    -- conservatively to 'untrusted' (issue #75 acceptance criterion).
    cap_email_verified_trust    text        NOT NULL,
    -- Whether the connector is active.
    enabled                     boolean     NOT NULL DEFAULT true,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connectors_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed email-verified-trust set: an unknown level can never be written.
    CONSTRAINT connectors_email_verified_trust_known
        CHECK (cap_email_verified_trust IN ('untrusted', 'trusted')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- A connector slug is unique per (tenant, environment).
CREATE UNIQUE INDEX connectors_slug_idx
    ON connectors (tenant_id, environment_id, connector_slug);
-- The management list and the config-snapshot export read a scope's connectors
-- ordered by (created_at, id).
CREATE INDEX connectors_scope_idx
    ON connectors (tenant_id, environment_id, created_at, id);

ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors FORCE ROW LEVEL SECURITY;
CREATE POLICY connectors_tenant_isolation ON connectors
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane (the management API) owns the connector lifecycle: create,
-- list/get, update, and delete. It seals the client secret inline on this row, for
-- which it holds the KEK/DEK provisioning grants (issue #37). COLUMN-scoped UPDATE
-- only (the #31 least-privilege lesson).
GRANT SELECT, INSERT, DELETE ON connectors TO ironauth_control;
GRANT UPDATE (
    definition_json, client_secret_sealed, client_secret_dek_version,
    cap_refresh, cap_groups, cap_logout_propagation, cap_email_verified_trust,
    enabled, updated_at
) ON connectors TO ironauth_control;
-- The DATA plane reads a connector's definition and opens its sealed client secret
-- to authenticate to the upstream at federation login time (the fetch itself rides
-- the SSRF-hardened path). SELECT only: the data plane never mutates a connector.
GRANT SELECT ON connectors TO ironauth_app;
