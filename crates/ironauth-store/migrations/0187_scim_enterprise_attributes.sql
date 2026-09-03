-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0187: the SCIM Enterprise User extension attributes, per CONNECTION (issue #135, criterion 2).
--
-- RFC 7643 section 4.3 defines seven attributes an identity provider sends alongside a user:
-- `employeeNumber`, `costCenter`, `organization`, `division`, `department`, `employeeType` and
-- the complex `manager`. This surface PUBLISHED that extension in `/Schemas` from the day it
-- shipped and parsed none of it, so an Entra push carrying them was answered 201 Created with
-- the attributes discarded.
--
-- WHY NOT IDENTITY TRAITS, which is where an earlier revision of this work put them.
--
-- Traits live on the `users` row and are ENVIRONMENT-WIDE. A review drove what that means with
-- two organizations that both hold one person: Acme created them with
-- `employeeNumber: "ACME-SECRET-701"`, and Globex's own connection token READ it back and then
-- OVERWROTE `department`, which Acme's next read returned. That is not a bug in the mapping, it
-- is the storage being the wrong shape: an employee number is the number that person has AT
-- THAT ORGANIZATION, and two organizations provisioning one human legitimately have different
-- ones.
--
-- It is the same argument 0184 makes for `externalId`, and the same namespace: the CONNECTION.
-- Keyed that way, "what does this identity provider say about this person" is unambiguous for
-- every provider at once, and revoking a connection leaves its attributes addressable for an
-- operator reconstructing what it did.
--
-- Two more things fell out of the trait storage that this shape removes rather than fixes. The
-- write was a read-modify-write across two transactions, and a review measured six concurrent
-- PATCHes answering 200 with five of them lost; here one row is one connection's whole
-- document, written in one statement. And `set_traits` validates against the environment's
-- ACTIVE trait schema, so an operator who had not declared these attributes had a surface that
-- refused them -- and the refusal landed AFTER the account was created.
--
-- ONE ROW PER (connection, user), holding the whole extension as JSON.
--
-- Not a column per attribute. The set is fixed by RFC 7643 today and the handler refuses
-- anything outside it, so a column per attribute would be defensible -- but `manager` is a
-- complex attribute whose sub-attributes the RFC lets a server extend, and a table that had to
-- migrate for a sub-attribute is a table that discourages carrying what an IdP actually sends.
-- The document is opaque to the database and validated by the handler against the published
-- schema, which is where the vocabulary already lives.

CREATE TABLE scim_enterprise_attributes (
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The connection whose namespace these attributes live in.
    connection_id      text        NOT NULL,
    -- The person they describe.
    user_id            text        NOT NULL,
    -- The extension document, exactly as the handler validated it. An OBJECT, enforced here so
    -- a hand-edited row cannot make a read return an array the renderer would emit as one.
    attributes         jsonb       NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_enterprise_attributes_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scim_enterprise_attributes_is_object
        CHECK (jsonb_typeof(attributes) = 'object'),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The user must exist. Users are soft-deleted, so a row never dangles.
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- ONE DOCUMENT PER (connection, user), which is what makes the write a single upsert rather
-- than a read-modify-write. The lost-update window the trait storage had is not narrowed here,
-- it is absent: there is nothing to read first.
CREATE UNIQUE INDEX scim_enterprise_attributes_by_user
    ON scim_enterprise_attributes (tenant_id, environment_id, connection_id, user_id);

ALTER TABLE scim_enterprise_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_enterprise_attributes FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_enterprise_attributes_scope ON scim_enterprise_attributes
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns it, for the reason 0184 gives: these are written when an IdP provisions a
-- person, which is a SCIM request on the data plane.
--
-- The UPDATE is COLUMN-SCOPED to what the upsert's SET list names, per the issue #31 lesson and
-- the rule 0186's header spells out: a REVOKE clears both grant forms, so this is the whole
-- intended set in one statement. `connection_id` and `user_id` are absent deliberately -- they
-- are the row's identity, and a data plane that could repoint either could move one identity
-- provider's attributes onto another's person.
GRANT SELECT, INSERT ON scim_enterprise_attributes TO ironauth_app;
GRANT UPDATE (attributes, updated_at) ON scim_enterprise_attributes TO ironauth_app;

-- A DELETE, unlike 0184's table, and the difference is what the two hold. An `externalId` is
-- how an IdP finds a person again after a delete, so removing it would break a rehire. These
-- are ATTRIBUTES: `{"op":"remove","path":"...:department"}` is an ordinary provisioning act,
-- and a server that answered "unsupported" to it would be making a false statement about an
-- attribute it publishes as readWrite. Clearing the last one leaves an empty document rather
-- than a missing row, so the DELETE is for the row's own lifecycle and nothing calls it yet --
-- it is granted with the read below on the same precedent 0184 records.
GRANT SELECT ON scim_enterprise_attributes TO ironauth_control;
