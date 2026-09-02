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
    -- The provisioning client's own identifier. Never PARSED by this server: its shape is the
    -- identity provider's business. Two paths compare it and they do not agree on case. The
    -- indexed lookup below is byte exact (it is a btree probe on this column), while a
    -- `filter=externalId eq ...` that falls through to the membership scan is evaluated by the
    -- SCIM filter evaluator, which case-folds per RFC 7643 section 2.1. So a stored `okta-77`
    -- is found by `OKTA-77` through the scan and not through the index. Recorded here rather
    -- than asserted away: making them agree means choosing which relation is right for a
    -- column the specification gives no uniqueness or case rule for, which is a decision this
    -- table does not get to make alone.
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
-- A second bind of the same `externalId` under one connection is a CONFLICT the handler answers
-- as SCIM 409. What this index guarantees is exactly that: ONE mapping row per (connection,
-- externalId). It does NOT by itself stop a retried provisioning run from creating a duplicate
-- person -- the account, its identifier row and its organization membership are written before
-- the bind, so a create that reached this index having already committed those would answer
-- 409 with the person created anyway. The handler therefore resolves the externalId BEFORE it
-- writes anything, and this index is the authority for the concurrent pair that both pass that
-- check.
--
-- On the status: RFC 7644 section 3.3 gives 409 for a uniqueness violation, but RFC 7643
-- section 3.1 puts no uniqueness constraint on `externalId`, so the 409 is this server's
-- choice for its own per-connection namespace rather than something the specification
-- requires.
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

-- The CONTROL plane reads. NO CALLER YET: nothing on the management plane reads this table
-- today, and by the standard this file applies three lines up (a DELETE grant would be "a
-- capability with no caller") that makes this one too. It is granted anyway, and the reason is
-- the precedent 0087 records: deferring a grant the design already knows it needs produced the
-- 0027-then-0084 revoke-and-re-grant churn on `organizations`. The operator-facing question
-- this answers -- "what did this connection provision" after it was revoked -- is owned by the
-- self-service portal issue, and a SELECT confers no ability to change anything.
GRANT SELECT ON scim_external_ids TO ironauth_control;

COMMENT ON TABLE scim_external_ids IS
    'Issue #135: the provisioning client''s own identifier for a person, namespaced per SCIM '
    'connection because two IdPs can use the same externalId for different people.';
COMMENT ON COLUMN scim_external_ids.external_id IS
    'Issue #135: never parsed by this server; its shape is the identity provider''s business. '
    'The indexed lookup compares it byte for byte and the filter scan case-folds it; see the '
    'column comment in migration 0184 for why both exist.';
