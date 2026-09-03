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
-- THE KEY IS THE ORGANIZATION, not the connection, and the difference is not cosmetic.
--
-- 0184 keys `externalId` per CONNECTION because an external id is the IDENTITY PROVIDER's own
-- handle for a person: Okta's is a directory id, Entra's is an object id, and two providers
-- naming one person differently is correct. An employee number is not that. It is a fact the
-- ORGANIZATION holds about the person, and two connections into one organization -- Okta and
-- Entra during a cutover, or the old and new rows of a credential rotation -- are describing
-- the same fact.
--
-- A first revision of this table keyed it per connection, and a review measured what that
-- costs: `scim_connections` grants UPDATE only on `(revoked_at, updated_at)`, so a token
-- rotation is necessarily a NEW row with a new id, and every attribute the old connection wrote
-- became unreadable through the surface. The attributes were stranded by a routine credential
-- rotation.
--
-- Two more things fell out of the trait storage that this shape removes rather than fixes. The
-- write was a read-modify-write across two transactions, and a review measured six concurrent
-- PATCHes answering 200 with five of them lost; here one row is one connection's whole
-- document, written in one statement. And `set_traits` validates against the environment's
-- ACTIVE trait schema, so an operator who had not declared these attributes had a surface that
-- refused them -- and the refusal landed AFTER the account was created.
--
-- ONE ROW PER (organization, user), holding the whole extension as JSON.
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
    -- The organization whose view of this person these attributes are.
    organization_id    text        NOT NULL,
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
    -- BOTH ENDS EXIST. `organization_id` is the isolation boundary this table is keyed on, so
    -- unlike 0184's `connection_id` -- which names a credential and is not a boundary -- it
    -- carries a foreign key: a row that named an organization the database does not have would
    -- be a boundary with nothing behind it.
    FOREIGN KEY (organization_id) REFERENCES organizations (id),
    -- The user must exist. Users are soft-deleted, so a row never dangles.
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- ONE DOCUMENT PER (organization, user), which is what makes the write a single upsert rather
-- than a read-modify-write. The lost-update window the trait storage had is not narrowed here,
-- it is absent: there is nothing to read first.
CREATE UNIQUE INDEX scim_enterprise_attributes_by_user
    ON scim_enterprise_attributes (tenant_id, environment_id, organization_id, user_id);

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
-- intended set in one statement. `organization_id` and `user_id` are absent deliberately -- they
-- are the row's identity, and a data plane that could repoint either could move one identity
-- provider's attributes onto another's person.
GRANT SELECT, INSERT ON scim_enterprise_attributes TO ironauth_app;
GRANT UPDATE (attributes, updated_at) ON scim_enterprise_attributes TO ironauth_app;

-- NO DELETE, and the paragraph that used to sit here claimed one. It argued for a DELETE grant
-- at length and the file issued none -- a review measured `has_table_privilege` false and the
-- statement refused -- which would have frozen a false sentence into a checksummed file.
--
-- None is needed. Clearing every attribute leaves an EMPTY DOCUMENT, not a missing row:
-- `{"op":"remove"}` and a `PUT` that omits the extension both express themselves as the value
-- of `attributes`, so the row's lifecycle is entirely within the UPDATE granted above. A row
-- with `{}` and no row at all render identically, and the handler treats them the same.
GRANT SELECT ON scim_enterprise_attributes TO ironauth_control;
