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
-- THE WHOLE PERSON IS SEALED, NOT JUST THE ADDRESS. Both columns that identify a human -- the
-- name and the address -- are envelope ciphertext under the tenant's DEK, because the property
-- worth having is that whoever can read this table cannot thereby learn who a customer's staff
-- are, and a plaintext name defeats that on its own. The blind index over the address is the one
-- deterministic value here, and it is an HMAC that reveals no address it did not already have.
--
-- ONE ORGANIZATION PER CONTACT, and it is fixed at insert: no path updates `organization_id`,
-- and the column-scoped grant below cannot. The caller DOES supply it -- every write takes a
-- scope-checked `OrganizationId` -- so what this column guarantees is not that the caller was
-- silent but that a contact cannot later be moved onto another organization's list.
CREATE TABLE org_contacts (
    -- The `oct_` scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- THE boundary: the one organization whose notifications this person receives.
    organization_id   text        NOT NULL,
    -- WHO THEY ARE, SEALED UNDER THE SAME DEK AS THE ADDRESS AND FOR THE SAME REASON. A
    -- contact's name is a customer's staff member's name: a table holding "Jane Okafor, security"
    -- next to a sealed address still tells whoever reads it who a customer's security lead is,
    -- which is precisely what sealing the address is for. The listing opens both, and it already
    -- fetches the DEK per row to open the address, so this costs the read nothing. Nothing orders
    -- or searches by it -- the listing is by `created_at, id` -- so no index needs it readable.
    display_name_sealed bytea     NOT NULL,
    -- WHERE THE NOTIFICATION GOES, SEALED. An address is classified PII in this system and every
    -- other table holding one seals it (0048 for the factor recipients, 0155 for a queued
    -- message), for the reason those state: whoever can read this table must not thereby learn
    -- who a customer's staff are. TWO READERS OPEN IT, not one: a sender at delivery time, and
    -- the management listing on every call, because an operator managing the list has to see the
    -- address they are managing. So the seal is not "opened once, at the edge" -- it is opened
    -- wherever the address is legitimately shown, and what it protects against is the reader who
    -- has the TABLE and not the key.
    email_sealed      bytea       NOT NULL,
    -- THE BLIND INDEX, a deterministic per-tenant keyed HMAC of the address (issue #48). It is
    -- what the duplicate rule keys on, because a ciphertext cannot be compared: two seals of one
    -- address differ, so a unique index over `email_sealed` would refuse nothing.
    email_bidx        bytea       NOT NULL,
    -- Which DEK sealed BOTH the name and the address, so either can be opened after a rotation.
    -- ONE VERSION FOR THE PAIR, because one write seals them together under one DEK and two AAD
    -- labels; they cannot come from different generations, so a second column would be a fact
    -- with two homes that nothing keeps in step.
    pii_dek_version   integer     NOT NULL,
    -- WHICH KIND OF NOTIFICATION THEY WANT, as a closed set. Adding one is a migration, which is
    -- the point: a category nothing can be routed to is a promise the product cannot keep, and a
    -- free string becomes a de facto enum whose members nobody can enumerate.
    category          text        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Set when the contact is removed. A DELETE would take the audit trail's referent with it:
    -- "who was notified about the certificate that then expired" is answerable only while the
    -- row survives, and both writes to this table carry an `org_contact.*` audit row that names
    -- this identifier.
    deleted_at        timestamptz,

    CONSTRAINT org_contacts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT org_contacts_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    -- EVERY SEALED COLUMN AND THE INDEX ARE PRESENT OR THE ROW IS UNUSABLE. A seal with no index
    -- cannot be deduplicated, an index with no seal is a contact nothing can be delivered to, and
    -- a row with no name is one an operator cannot act on; each is a row a reader can only fail
    -- on.
    CONSTRAINT org_contacts_sealed_columns_complete
        CHECK (octet_length(email_sealed) > 0
               AND octet_length(email_bidx) > 0
               AND octet_length(display_name_sealed) > 0),
    -- THE SHAPE OF WHAT IS SEALED IS CHECKED WHERE IT IS READABLE, which is the repository: a
    -- CHECK cannot see through a seal, so neither the address's shape nor the name's ceiling can
    -- be stated here. `ActingOrgContactRepo::add` holds both and refuses before it seals. Stated
    -- because the absence is otherwise a gap a reader must notice rather than a decision somebody
    -- made. The category is NOT sealed -- it is a closed set of three vendor-chosen words, tells
    -- nobody who anybody is, and the notification path selects on it -- so it keeps its CHECK.
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
