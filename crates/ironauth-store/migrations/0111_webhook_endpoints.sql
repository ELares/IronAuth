-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Standard Webhooks endpoint registration (issue #105, the slice after the signing
-- contract in #554).
--
-- One row is one registered delivery target for an environment: where to POST, whether
-- it is active, and the SIGNING SECRET the deliverer MACs with. The signing contract
-- itself is `ironauth_jose::webhooks`; this is where the secret it needs lives.
--
-- THE SECRET IS SEALED, NOT HASHED, and the difference is forced by what it is for. A
-- management key is hashed because verification only needs to compare. A webhook secret
-- must be RECOVERED to compute an HMAC over every delivery, so it is sealed under the
-- scope's active DEK exactly as `connectors.client_secret_sealed` is (0056, issue #48),
-- and it is revealed to the operator exactly once at creation.
--
-- The grant split follows the connector precedent for the same reason it exists there.
-- The CONTROL plane owns the lifecycle (register, list, deactivate, delete) and seals the
-- secret inline, holding the KEK/DEK provisioning grants. The DATA plane only READS: the
-- outbox consumer that delivers opens the sealed secret to sign, and never mutates an
-- endpoint. Column-scoped UPDATE on the control side, per the #31 lesson.
--
-- `url` is HTTPS-only, enforced above this layer at the admin surface rather than by a
-- CHECK, because the same rule has to reject a loopback or otherwise internal host too
-- and that is the SSRF-hardened fetcher's judgement, not a constraint's.

CREATE TABLE webhook_endpoints (
    -- The `whe_` scoped identifier; embeds its (tenant, environment).
    id                    text        PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- The HTTPS destination a delivery POSTs to.
    url                   text        NOT NULL,
    -- A human label for the operator listing endpoints. Never secret.
    description           text        NOT NULL DEFAULT '',
    -- Whether deliveries are dispatched. A deactivated endpoint keeps its secret and its
    -- history rather than being deleted, so it can be resumed without re-registering.
    active                boolean     NOT NULL DEFAULT true,
    -- The Standard Webhooks signing secret, sealed under the scope's active DEK.
    secret_sealed         bytea       NOT NULL,
    -- The DEK version the secret was sealed under.
    secret_dek_version    integer     NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_endpoints_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT webhook_endpoints_url_nonempty
        CHECK (url <> '')
);

-- The listing key, and the key the deliverer reads by.
CREATE INDEX webhook_endpoints_scope_created_idx
    ON webhook_endpoints (tenant_id, environment_id, created_at, id);

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

GRANT SELECT, INSERT, DELETE ON webhook_endpoints TO ironauth_control;
GRANT UPDATE (url, description, active, secret_sealed, secret_dek_version, updated_at)
    ON webhook_endpoints TO ironauth_control;
-- SELECT only: the deliverer opens the sealed secret to sign and never mutates a row.
GRANT SELECT ON webhook_endpoints TO ironauth_app;
