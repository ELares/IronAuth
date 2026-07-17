-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Enterprise inbound federation: org connections and domain routing (issue #77, PR 1).
--
-- Inbound enterprise SSO routes a login to an organization's upstream identity
-- provider by email domain (or by app or by user), then provisions the local
-- identity just in time. This migration lands the two configuration tables that
-- machinery reads, plus the correlation-row column that binds a routed login to its
-- organization across the authorize and callback legs.
--
--   org_connections: one row per (organization, connector) binding per environment.
--     It ties an organization to the declarative connector (issue #75) that describes
--     its upstream, and carries the broker overlay policy columns that a later PR
--     fills and enforces (shipped NULLABLE and unused now). It holds:
--       - a scope embedded `ocn_` id (embeds its (tenant, environment), so a binding
--         minted in one scope parses as a uniform not found under another);
--       - organization_id: the `org_` organization this binding belongs to;
--       - connector_id: the `cnr_` connector describing its upstream;
--       - overlay_min_acr / max_age_secs / overlay_min_class: the broker overlay
--         policy a later PR composes and enforces on top of the upstream (shipped
--         NULLABLE and unread now). overlay_min_class is pinned to the credential
--         class ladder;
--       - capture_upstream_tokens: whether a later PR persists the upstream tokens
--         after a brokered login (shipped, but not consumed yet);
--       - enabled: whether the binding is active.
--     Classified Promotable (issue #41): the binding is per environment configuration
--     a config snapshot carries, and it holds NO secret column.
--
--   routing_rules: one row per routing rule per environment. A rule maps EXACTLY ONE
--     selector (an email domain, an app client, or a single user) to an org connection
--     with a priority. It holds:
--       - a scope embedded `rrl_` id;
--       - rule_kind: which selector this rule carries (a closed CHECK set);
--       - domain_norm / client_id / user_bidx: the selector, of which EXACTLY ONE is
--         non NULL per the kind. domain_norm is NFKC normalized and case folded;
--         user_bidx is a BLIND INDEX of the canonical login identifier, never the
--         plaintext (no plaintext user selector column ever exists);
--       - org_connection_id: the org connection a matching login routes to;
--       - priority / enabled.
--     THREE partial UNIQUE indexes, one per selector scope, are the STRUCTURAL routing
--     confusion defense: within a scope one domain, one app, or one user can map to at
--     most one enabled org connection, so a login can never be routed to two
--     organizations. Classified Promotable and snapshot exported (user_bidx is opaque).
--
--   federation_login_states.org_connection_id: the routed org connection is written on
--     the AUTHORIZE leg into the single use correlation row, so the CALLBACK re derives
--     the organization from the CONSUMED row, never from anything the browser sent.
--     NULLABLE: a direct federated login that was not routed to an organization carries
--     no binding.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant scoped table ENABLES
-- and FORCES row level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment organization to connector binding (issue #77).
CREATE TABLE org_connections (
    -- The ocn_ scoped identifier; embeds its (tenant, environment).
    id                      text        PRIMARY KEY,
    tenant_id               text        NOT NULL,
    environment_id          text        NOT NULL,
    -- The organization this binding belongs to (an org_ id).
    organization_id         text        NOT NULL,
    -- The connector describing this organization's upstream (a cnr_ id).
    connector_id            text        NOT NULL,
    -- The broker overlay policy a later PR composes and enforces (shipped NULLABLE and
    -- unread now): a minimum acr floor, a maximum authentication age, and a minimum
    -- credential class the broker overlays on top of the upstream.
    overlay_min_acr         text,
    max_age_secs            integer,
    overlay_min_class       text,
    -- Whether a later PR persists the upstream tokens after a brokered login (shipped,
    -- not consumed yet).
    capture_upstream_tokens boolean     NOT NULL DEFAULT false,
    -- Whether the binding is active.
    enabled                 boolean     NOT NULL DEFAULT true,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_connections_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The overlay minimum class, when set, is one rung of the credential class ladder
    -- (the SAME closed set as credential_class_policies, issue #66); an unknown class
    -- can never be written.
    CONSTRAINT org_connections_overlay_min_class_known
        CHECK (overlay_min_class IS NULL
               OR overlay_min_class IN ('any', 'mfa', 'passkey', 'attested_passkey')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- One organization maps a given connector at most once per (tenant, environment).
CREATE UNIQUE INDEX org_connections_org_connector_idx
    ON org_connections (tenant_id, environment_id, organization_id, connector_id);
-- The management list and the config snapshot export read a scope's bindings ordered
-- by the stable (created_at, id) key.
CREATE INDEX org_connections_scope_idx
    ON org_connections (tenant_id, environment_id, created_at, id);

ALTER TABLE org_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY org_connections_tenant_isolation ON org_connections
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane reads a binding to route a login and to bind provisioning to the
-- organization. The CONTROL plane owns the lifecycle (create) and reads for the
-- snapshot export. Neither column carries a secret, so no sealing is involved.
GRANT SELECT ON org_connections TO ironauth_app;
GRANT SELECT, INSERT ON org_connections TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The per environment routing rule (issue #77).
CREATE TABLE routing_rules (
    -- The rrl_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- Which selector this rule carries (a closed set).
    rule_kind          text        NOT NULL,
    -- The selector, of which EXACTLY ONE is non NULL per the rule_kind (the kind to
    -- selector CHECK below). domain_norm is NFKC normalized and case folded; client_id
    -- is an OAuth client id; user_bidx is a BLIND INDEX of the canonical login
    -- identifier, never the plaintext.
    domain_norm        text,
    client_id          text,
    user_bidx          bytea,
    -- The org connection a matching login routes to (an ocn_ id).
    org_connection_id  text        NOT NULL,
    -- The evaluation priority (higher first within a kind); the structural uniqueness
    -- below already makes at most one enabled rule match a given selector in a scope.
    priority           integer     NOT NULL DEFAULT 0,
    enabled            boolean     NOT NULL DEFAULT true,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT routing_rules_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed selector kind set: an unknown kind can never be written.
    CONSTRAINT routing_rules_kind_known
        CHECK (rule_kind IN ('domain', 'app', 'user')),
    -- EXACTLY ONE selector per kind: a domain rule carries only domain_norm, an app
    -- rule only client_id, a user rule only user_bidx. A rule can never carry two
    -- selectors or none.
    CONSTRAINT routing_rules_selector_matches_kind CHECK (
        (rule_kind = 'domain'
            AND domain_norm IS NOT NULL AND client_id IS NULL AND user_bidx IS NULL)
        OR (rule_kind = 'app'
            AND client_id IS NOT NULL AND domain_norm IS NULL AND user_bidx IS NULL)
        OR (rule_kind = 'user'
            AND user_bidx IS NOT NULL AND domain_norm IS NULL AND client_id IS NULL)
    ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The STRUCTURAL routing confusion defense (issue #77): three partial UNIQUE indexes,
-- one per selector scope, each over (tenant, environment, selector) WHERE the rule is
-- enabled. Within a scope one domain, one app, or one user maps to at most one enabled
-- org connection, so a login can never be routed to two organizations. A second
-- conflicting mapping is REJECTED by the storage engine, not by an application check.
CREATE UNIQUE INDEX routing_rules_domain_uniq
    ON routing_rules (tenant_id, environment_id, domain_norm)
    WHERE enabled AND rule_kind = 'domain';
CREATE UNIQUE INDEX routing_rules_app_uniq
    ON routing_rules (tenant_id, environment_id, client_id)
    WHERE enabled AND rule_kind = 'app';
CREATE UNIQUE INDEX routing_rules_user_uniq
    ON routing_rules (tenant_id, environment_id, user_bidx)
    WHERE enabled AND rule_kind = 'user';
-- The management list and the config snapshot export read a scope's rules ordered by
-- the stable (created_at, id) key.
CREATE INDEX routing_rules_scope_idx
    ON routing_rules (tenant_id, environment_id, created_at, id);

ALTER TABLE routing_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_rules_tenant_isolation ON routing_rules
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane reads rules to route a login; the CONTROL plane owns the lifecycle
-- (create) and reads for the snapshot export.
GRANT SELECT ON routing_rules TO ironauth_app;
GRANT SELECT, INSERT ON routing_rules TO ironauth_control;

-- ---------------------------------------------------------------------------
-- Bind a routed federated login to its organization across the two legs (issue #77).
-- The AUTHORIZE leg writes the routed org connection into the single use correlation
-- row; the CALLBACK reads it back from the CONSUMED row, so the organization the
-- callback provisions against is never influenced by anything the browser sent.
-- NULLABLE: a direct federated login that was not routed to an organization carries no
-- binding, exactly as before this migration. Additive, so this is an EXPAND. The
-- existing table level INSERT grant to ironauth_app already covers the new column.
ALTER TABLE federation_login_states
    ADD COLUMN org_connection_id text;

-- ---------------------------------------------------------------------------
-- Stamp the organization binding on the provisioned user (issue #77). A JIT provisioned
-- federated identity records which org connection routed it, so a returning login keeps
-- the SAME (issuer, sub) identity (issue #75 HIGH-1) while its organization binding is
-- refreshed. NULLABLE: a user not provisioned through org routing carries no binding.
-- Not PII (an ocn_ id is a public scoped handle), so it is a plain column, never sealed.
-- Additive, so this is an EXPAND. A column scoped UPDATE grant lets the data plane
-- provisioning path stamp it; the control plane may set it through the management API.
ALTER TABLE users
    ADD COLUMN org_connection_id text;
GRANT UPDATE (org_connection_id) ON users TO ironauth_app;
GRANT UPDATE (org_connection_id) ON users TO ironauth_control;
