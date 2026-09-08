-- Read-only LDAP/AD inbound sync: the connector (issue #142).
--
-- One row is one directory IronAuth reads FROM. The sync itself, the snapshot diffing and the
-- scheduling land in later slices; this is the configuration they all read, and it comes first
-- because everything else is a consumer of it.
--
-- PER ORGANIZATION, for the reason `scim_connections` and `scim_push_connections` both are: a
-- directory credential that could write into two organizations is the IDOR this model exists to
-- make unrepresentable. A deployment federating three customers runs three connectors.
--
-- THE BIND PASSWORD IS NOT A COLUMN. `bind_secret_name` names an `environment_secrets` row, the
-- way 0189 and 0144 do, and the value is resolved at bind time through the sealing path that
-- already exists. Two reasons, both 0189's: a second sealed column is a second sealing path to
-- get right, and naming the secret gives rotation for free -- an operator rotates the secret and
-- every connector naming it follows.
--
-- NO SYNC STATE HERE. Last-run time, counts, cursor and health belong to the RUN, not the
-- configuration, and putting them on this row would make every status write contend with every
-- configuration read. They land with the scheduler slice, in their own table.

CREATE TABLE ldap_connectors (
    -- The `ldc_` scoped identifier; embeds its (tenant, environment).
    id                    text        NOT NULL PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,
    -- The one organization whose users and groups this directory populates.
    organization_id       text        NOT NULL,
    -- What an operator calls it in the console.
    display_name          text        NOT NULL,

    -- WHERE. Host and port separately rather than a URL, because the TLS MODE is a separate
    -- decision below and a URL scheme would encode it twice -- `ldaps://` in the host and
    -- `tls_mode` in the column, free to disagree.
    host                  text        NOT NULL,
    port                  integer     NOT NULL,

    -- HOW THE CONNECTION IS PROTECTED. #142 requires LDAPS or StartTLS by DEFAULT and an
    -- explicit flag for plaintext, so the insecure choice has to be a value somebody typed --
    -- not the absence of a value they forgot.
    tls_mode              text        NOT NULL DEFAULT 'ldaps',

    -- WHO WE BIND AS. The DN is configuration; the password is a secret NAME (see the header).
    bind_dn               text        NOT NULL,
    bind_secret_name      text        NOT NULL,

    -- WHAT TO READ. Separate base DNs because a directory routinely keeps people and groups in
    -- different subtrees, and one base covering both means reading everything and filtering in
    -- the client -- which is the N+1 shape #142 cites authentik for.
    user_base_dn          text        NOT NULL,
    group_base_dn         text        NOT NULL,
    user_filter           text        NOT NULL,
    group_filter          text        NOT NULL,

    -- HOW ATTRIBUTES BECOME IDENTITY. A flat `{ "canonical field": "source attribute" }`
    -- object: the shape the SCIM push path uses, and deliberately that one rather than
    -- `saml_connections.attribute_mapping`, which is a DIFFERENT shape -- a typed
    -- `ClaimMapping { subject, traits }` with `deny_unknown_fields`, built for pulling claims out
    -- of an assertion. #142 asks for one attribute-mapping mental model across the two
    -- provisioning paths, which are this column and the SCIM one; SAML sign-in is a third thing
    -- and is not it.
    attribute_mapping     jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- WHAT ABSENCE MEANS. #142's deletion-propagation criterion: a user gone from the directory
    -- is deactivated (default) or deleted, per connector. Named on the connector rather than
    -- assumed, because the answer differs by customer -- a contractor directory prunes, an
    -- employee directory keeps the record for audit.
    absence_policy        text        NOT NULL DEFAULT 'deactivate',

    -- HOW DEEP NESTED GROUPS RESOLVE. Bounded, because #142 asks for a cycle fixture that
    -- "terminates cleanly at bounded depth" -- and a cycle in a directory is not exotic, it is
    -- what happens when two groups list each other.
    max_group_depth       integer     NOT NULL DEFAULT 10,

    -- Whether the scheduler picks it up. An operator turning a connector off must not have to
    -- delete its configuration to stop it.
    active                boolean     NOT NULL DEFAULT true,

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ldap_connectors_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT ldap_connectors_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    CONSTRAINT ldap_connectors_display_name_shaped
        CHECK (display_name <> '' AND octet_length(display_name) <= 256),
    -- A CLOSED SET, so a handler matching on it has no arm to guess at, and so `plaintext`
    -- cannot be reached by a typo in a free-text column.
    CONSTRAINT ldap_connectors_tls_mode_known
        CHECK (tls_mode IN ('ldaps', 'starttls', 'plaintext')),
    CONSTRAINT ldap_connectors_absence_policy_known
        CHECK (absence_policy IN ('deactivate', 'delete')),
    CONSTRAINT ldap_connectors_host_shaped
        CHECK (host <> '' AND octet_length(host) <= 255),
    CONSTRAINT ldap_connectors_port_ranged
        CHECK (port > 0 AND port <= 65535),
    CONSTRAINT ldap_connectors_bind_dn_shaped
        CHECK (bind_dn <> '' AND octet_length(bind_dn) <= 1024),
    CONSTRAINT ldap_connectors_bind_secret_name_shaped
        CHECK (bind_secret_name <> '' AND octet_length(bind_secret_name) <= 252),
    CONSTRAINT ldap_connectors_base_dns_shaped
        CHECK (user_base_dn <> '' AND octet_length(user_base_dn) <= 1024
               AND group_base_dn <> '' AND octet_length(group_base_dn) <= 1024),
    CONSTRAINT ldap_connectors_filters_shaped
        CHECK (user_filter <> '' AND octet_length(user_filter) <= 4096
               AND group_filter <> '' AND octet_length(group_filter) <= 4096),
    -- A DEPTH OF ZERO RESOLVES NO NESTING AT ALL, which is a real choice (direct membership
    -- only) rather than a degenerate one, so zero is permitted and the ceiling is what is
    -- bounded. Above a few dozen the recursion is not a directory, it is a cycle the detector
    -- should have caught.
    CONSTRAINT ldap_connectors_max_group_depth_ranged
        CHECK (max_group_depth >= 0 AND max_group_depth <= 64),
    CONSTRAINT ldap_connectors_attribute_mapping_is_object
        CHECK (jsonb_typeof(attribute_mapping) = 'object'),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The scheduler reads every ACTIVE connector in a scope; an operator reads one organization's.
CREATE INDEX ldap_connectors_by_scope_idx
    ON ldap_connectors (tenant_id, environment_id) WHERE active;
CREATE INDEX ldap_connectors_by_org_idx
    ON ldap_connectors (tenant_id, environment_id, organization_id);

ALTER TABLE ldap_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_connectors FORCE ROW LEVEL SECURITY;

CREATE POLICY ldap_connectors_scope ON ldap_connectors
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Configuring a directory is an operator act on the control plane, like every other connector
-- here. DELETE is granted so a connector can be removed outright: unlike a grant or a
-- certificate, a connector row records no history worth keeping -- what it DID is in the audit
-- log and in the sync runs, neither of which this row owns.
GRANT SELECT, INSERT, DELETE ON ldap_connectors TO ironauth_control;
-- UPDATE is column-scoped to exactly what a statement writes, the shape 0189 uses. The only
-- UPDATE in the tree is `set_active`, which writes these two. A privilege for a write nothing
-- performs is one nobody can account for later, and here the withheld columns are the ones that
-- decide which organization the sync reads and how the connection is protected.
GRANT UPDATE (active, updated_at) ON ldap_connectors TO ironauth_control;

-- The DATA plane gets NOTHING. Nothing served on a request path reads a directory connector:
-- the sync is a background job on the control plane, and a token is minted from the users and
-- groups the sync already wrote. Granting SELECT here would widen the token-issuance role's
-- reach to a set of bind DNs and secret names for no path that needs them -- the same reasoning
-- 0120 gives for project grants.
