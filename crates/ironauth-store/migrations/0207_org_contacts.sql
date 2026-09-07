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
    -- WHERE THE NOTIFICATION GOES, SEALED. An address is classified PII in this system and every
    -- other table holding one seals it (0048 for the factor recipients, 0155 for a queued
    -- message), for the reason those state: whoever can read this table must not thereby learn
    -- who a customer's staff are. A sender opens it at delivery time; nothing else needs to.
    email_sealed      bytea       NOT NULL,
    -- THE BLIND INDEX, a deterministic per-tenant keyed HMAC of the address (issue #48). It is
    -- what the duplicate rule keys on, because a ciphertext cannot be compared: two seals of one
    -- address differ, so a unique index over `email_sealed` would refuse nothing.
    email_bidx        bytea       NOT NULL,
    -- Which DEK sealed the address, so it can be opened after a rotation.
    pii_dek_version   integer     NOT NULL,
    -- WHICH KIND OF NOTIFICATION THEY WANT, as a closed set. Adding one is a migration, which is
    -- the point: a category nothing can be routed to is a promise the product cannot keep, and a
    -- free string becomes a de facto enum whose members nobody can enumerate.
    category          text        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Set when the contact is removed. A DELETE would take the audit trail's referent with it:
    -- "who was notified about the certificate that then expired" is answerable only while the
    -- row survives, and both writes to this table carry an `org.contact.*` audit row that names
    -- this identifier.
    deleted_at        timestamptz,

    CONSTRAINT org_contacts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT org_contacts_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    CONSTRAINT org_contacts_display_name_shape
        CHECK (display_name <> '' AND octet_length(display_name) <= 256),
    -- THE SEALED ADDRESS AND ITS INDEX ARE BOTH PRESENT OR THE ROW IS UNUSABLE. A seal with no
    -- index cannot be deduplicated and an index with no seal is a contact nothing can be
    -- delivered to; either is a row the notification path can only fail on.
    CONSTRAINT org_contacts_sealed_address_complete
        CHECK (octet_length(email_sealed) > 0 AND octet_length(email_bidx) > 0),
    -- THE ADDRESS SHAPE IS CHECKED WHERE THE ADDRESS IS READABLE, which is the repository: a
    -- CHECK cannot see through a seal. Stated here because its absence is otherwise a gap a
    -- reader would have to notice, rather than a decision somebody made.
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
    ON org_contacts (tenant_id, environment_id, organization_id, category, email_bidx)
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
GRANT UPDATE (updated_at, deleted_at) ON org_contacts TO ironauth_control;

-- REMOVAL IS ONE WAY, and the grant cannot say so: `deleted_at` is exactly the column a removal
-- must write, so a role able to set it is able to clear it. A RESTRICTIVE policy is what makes it
-- one way, as 0205 does for a revoked token.
--
-- `USING (deleted_at IS NULL)` hides an already-removed row from any UPDATE, and the `WITH CHECK`
-- requires the result to be removed -- so a live row can only move to removed, and a removed row
-- cannot be touched at all. Without it the tombstone this table keeps for the audit trail could
-- be quietly un-set by the same role that wrote it.
CREATE POLICY org_contacts_removal_is_one_way ON org_contacts
    AS RESTRICTIVE
    FOR UPDATE
    TO ironauth_control
    USING (deleted_at IS NULL)
    WITH CHECK (deleted_at IS NOT NULL);

-- THE DATA PLANE READS, and only reads. The notification senders run there and need to know
-- where to deliver; nothing on that side may edit who is notified, because a delivery path that
-- could rewrite its own destinations is one an operator cannot audit.
GRANT SELECT ON org_contacts TO ironauth_app;
