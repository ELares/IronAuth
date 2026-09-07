-- The people an organization's operational notifications should reach (issue #141).
--
-- WHY A FIRST-CLASS OBJECT AND NOT A FIELD ON THE ORGANIZATION. #141's premise is that "the
-- person who set up SSO is rarely the person watching the vendor's status page": a certificate
-- expiring, a SCIM token approaching its lead time, or a connection degrading each need to reach
-- somebody who can act, and those are usually different people. One column would force one
-- answer for every category, and the failure it produces is silent -- the notification is sent,
-- to somebody who does not act on it, and the outage arrives anyway.
--
-- NOT USERS. A contact is a routing destination, not a principal: it authenticates nothing, holds
-- no session, and grants no access. Modelling it as a `users` row would create an account for
-- somebody who never signs in, and every membership and permission path would then have to reason
-- about a person who cannot. The email here is a delivery address and nothing more.
--
-- ONE ORGANIZATION, NAMED HERE AND NEVER BY THE CALLER, exactly as `scim_connections` does it.
CREATE TABLE org_contacts (
    -- The `oct_` scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- THE boundary: the one organization whose notifications this person receives.
    organization_id   text        NOT NULL,
    -- Who they are, for an operator reading the list.
    display_name      text        NOT NULL,
    -- Where the notification goes. Stored as given: this is a delivery address, and the
    -- messaging subsystem owns normalisation and send hygiene.
    email             text        NOT NULL,
    -- WHICH KIND OF NOTIFICATION THEY WANT, as a closed set. Adding one is a migration, which is
    -- the point: a category nothing can be routed to is a promise the product cannot keep, and a
    -- free string becomes a de facto enum whose members nobody can enumerate.
    category          text        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Set when the contact is removed. A DELETE would take the audit trail's referent with it:
    -- "who was notified about the certificate that then expired" is answerable only while the
    -- row survives.
    deleted_at        timestamptz,

    CONSTRAINT org_contacts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT org_contacts_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    CONSTRAINT org_contacts_display_name_shape
        CHECK (display_name <> '' AND octet_length(display_name) <= 256),
    -- AN ADDRESS THAT COULD BE DELIVERED TO. Deliberately shallow: a full grammar here would be
    -- wrong in both directions, refusing valid addresses and admitting undeliverable ones, and
    -- the authority on deliverability is the send path rather than a CHECK constraint. What this
    -- refuses is the shapes that are certainly not addresses.
    CONSTRAINT org_contacts_email_shape
        CHECK (email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'
               AND octet_length(email) <= 320),
    CONSTRAINT org_contacts_category_known
        CHECK (category IN ('technical', 'security', 'billing')),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization must EXIST, and that is all this key does: referential integrity checks
    -- BYPASS row-level security, so an id-only key admits any globally existing organization.
    -- What refuses a cross-scope one is the repository, which takes a scope-checked
    -- `OrganizationId`. `organizations` carries no `UNIQUE (id, tenant_id, environment_id)` to
    -- reference, so a composite key cannot say it here.
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The management listing: every live contact for one organization, oldest first.
CREATE INDEX org_contacts_by_org
    ON org_contacts (tenant_id, environment_id, organization_id, created_at, id);

-- ONE ADDRESS PER CATEGORY PER ORGANIZATION, among LIVE rows. Two contacts on the same category
-- and address are one person listed twice: the notification goes out twice and the operator
-- cannot tell which row to remove. Partial, so a removed contact does not block re-adding the
-- same person later -- which is the ordinary case when somebody rejoins a team.
CREATE UNIQUE INDEX org_contacts_live_address
    ON org_contacts (tenant_id, environment_id, organization_id, category, lower(email))
    WHERE deleted_at IS NULL;

ALTER TABLE org_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_contacts FORCE ROW LEVEL SECURITY;

CREATE POLICY org_contacts_scope ON org_contacts
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE CONTROL PLANE OWNS THE LIFECYCLE, because managing who a vendor notifies about their
-- customer's outages is an operator action and a portal one, both of which reach the management
-- API. UPDATE IS COLUMN SCOPED for the reason 0183 gives: a table-wide grant would let the role
-- re-point `organization_id` at another organization, which is the boundary this table exists to
-- hold.
GRANT SELECT, INSERT ON org_contacts TO ironauth_control;
GRANT UPDATE (display_name, email, category, updated_at, deleted_at) ON org_contacts
    TO ironauth_control;

-- THE DATA PLANE READS, and only reads. The notification senders run there and need to know
-- where to deliver; nothing on that side may edit who is notified, because a delivery path that
-- could rewrite its own destinations is one an operator cannot audit.
GRANT SELECT ON org_contacts TO ironauth_app;
