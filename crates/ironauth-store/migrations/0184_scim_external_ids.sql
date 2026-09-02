-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0184: the SCIM `externalId` mapping, per CONNECTION (issue #135, milestone M14).
--
-- RFC 7643's `externalId` is the PROVISIONING CLIENT's own identifier for a person, not this
-- server's. The client sends it on create and expects it back on every read, and it is how the
-- client answers "have I already provisioned this person here" without keeping a local map.
--
-- WHY THE NAMESPACE IS THE CONNECTION AND NOT THE ENVIRONMENT.
--
-- Two identity providers can provision into one organization, and nothing stops them using the
-- same `externalId` string for different people: Okta's is a directory id, Entra's is an object
-- id, and neither knows about the other. Keyed per environment, the second connection's first
-- create would either collide with the first connection's row or silently update somebody
-- else's person -- the worse of the two, because provisioning would appear to succeed.
--
-- Keyed per CONNECTION, "look this person up by the externalId my IdP knows" is unambiguous for
-- every IdP at once, and revoking a connection leaves its mappings addressable for an operator
-- reconstructing what it did.
--
-- WHY IT IS A SEPARATE TABLE rather than a column on `users`.
--
-- A column would hold ONE external id per person, and a person provisioned by two IdPs has two.
-- It would also make `users` carry a value that belongs to a credential rather than to the
-- person, so revoking a connection would either orphan the column or require rewriting user
-- rows -- neither of which is a thing a revocation should do.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it
-- inert.

CREATE TABLE scim_external_ids (
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The connection whose namespace this mapping lives in.
    connection_id      text        NOT NULL,
    -- The provisioning client's own identifier. Opaque to this server: it is compared byte for
    -- byte and never parsed, because its shape is the IdP's business.
    external_id        text        NOT NULL,
    -- The person it names here.
    user_id            text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_external_ids_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scim_external_ids_external_id_nonempty
        CHECK (external_id <> ''),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The user must exist. Users are soft-deleted, so a mapping never dangles.
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- THE NAMESPACE, as an index rather than a convention: one external id per connection.
--
-- A second create with the same `externalId` is a CONFLICT the handler answers as SCIM 409,
-- which is what RFC 7644 section 3.3 requires and what stops a retried provisioning run from
-- creating a duplicate person.
CREATE UNIQUE INDEX scim_external_ids_unique_per_connection
    ON scim_external_ids (tenant_id, environment_id, connection_id, external_id);

-- The round trip: given a person, what does THIS connection call them. One row per (connection,
-- user), so a read can attach the caller's own identifier without a scan.
CREATE UNIQUE INDEX scim_external_ids_by_user
    ON scim_external_ids (tenant_id, environment_id, connection_id, user_id);

ALTER TABLE scim_external_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_external_ids FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_external_ids_scope ON scim_external_ids
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns this one, unlike `scim_connections` next door, and the reason is where
-- the work happens: a mapping is written when an IdP provisions a person, which is a SCIM
-- request on the data plane. Routing it through the control plane would put an operator in the
-- middle of every provisioning run.
--
-- No DELETE. A mapping is not removed when a person is deprovisioned: `active = false` is a
-- lifecycle change on the USER, and the mapping is what lets the same IdP find that person
-- again to reactivate them. Nothing in this slice deletes one, and a DELETE grant would be a
-- capability with no caller.
GRANT SELECT, INSERT ON scim_external_ids TO ironauth_app;

-- The CONTROL plane reads, so an operator can answer "what did this connection provision"
-- after it has been revoked.
GRANT SELECT ON scim_external_ids TO ironauth_control;

COMMENT ON TABLE scim_external_ids IS
    'Issue #135: the provisioning client''s own identifier for a person, namespaced per SCIM '
    'connection because two IdPs can use the same externalId for different people.';
COMMENT ON COLUMN scim_external_ids.external_id IS
    'Issue #135: opaque to this server. Compared byte for byte and never parsed; its shape is '
    'the identity provider''s business.';
