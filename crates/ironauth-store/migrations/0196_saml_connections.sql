-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- SAML SP inbound: the connections an organization signs in through (issue #139).
--
-- IronAuth is the SERVICE PROVIDER here. An enterprise customer's identity provider asserts who
-- somebody is, and this table records which identity provider an organization trusts and on what
-- terms. It is the mirror of an OIDC org connection (0117) in purpose and nothing like it in
-- shape, because SAML's trust is a pinned KEY rather than a discovered issuer.
--
-- # The certificate is not the trust anchor. The KEY is.
--
-- Every SAML CVE in the "trusted the certificate inside the response" family (Casdoor
-- CVE-2026-9090 is the named one in #139) comes from treating a `KeyInfo` an attacker sent as
-- something to verify against. `ironauth-saml`'s verifier takes a `TrustAnchor`, which is an
-- `XmlSigKey`: raw EC point or RSA modulus and exponent, deliberately NOT a DER certificate, so
-- that an X.509 parser is never on the path of attacker-adjacent bytes.
--
-- That decision is why this schema has two columns where a naive one would have one. The
-- certificate an operator uploads is parsed ONCE, at configuration time, and both halves are
-- kept: `public_key` is what the verifier is handed, and `certificate_der` is what an operator
-- sees and what expiry is read from. Nothing on the assertion path ever reads the certificate.
--
-- # Certificates are plural from the start, because rotation is not an edge case
--
-- An identity provider's signing certificate expires, and the customer rotates it on their
-- schedule, not ours. If a connection could pin only one, every rotation would be an outage
-- bounded by how fast somebody noticed. So the pins live in a child table and any live one
-- verifies: an operator adds the new certificate before the IdP switches, and removes the old one
-- afterwards. Issue #141 builds expiry alerting and a renewal flow on exactly this shape.

CREATE TABLE saml_connections (
    id                       text        PRIMARY KEY,
    tenant_id                text        NOT NULL,
    environment_id           text        NOT NULL,
    -- The organization whose people sign in through this identity provider. Per organization for
    -- the reason every other connection is: a trust anchor that reached two organizations would
    -- let one customer's identity provider assert another customer's users.
    organization_id          text        NOT NULL,
    display_name             text        NOT NULL,

    -- WHAT THE IDENTITY PROVIDER CALLS ITSELF. The `Issuer` of a response must equal this, which
    -- is what stops a response signed by a legitimately pinned key of one connection being
    -- replayed into another.
    idp_entity_id            text        NOT NULL,
    -- Where an AuthnRequest is sent (HTTP-Redirect binding).
    idp_sso_url              text        NOT NULL,

    -- WHAT THIS DEPLOYMENT CALLS ITSELF TO THIS IDENTITY PROVIDER, and the value in force is
    -- stored rather than derived at validation time.
    --
    -- Derivation is what makes an audience check drift: the environment's base URL changes, every
    -- stored connection silently starts expecting a different `Audience`, and every customer's
    -- IdP is still asserting the old one. Storing it means a rename is an explicit re-pinning
    -- that an operator and their customer coordinate, which is what SAML metadata exchange is.
    sp_entity_id             text        NOT NULL,
    -- The assertion consumer service URL this connection's responses must name, for the
    -- `Destination` and `Recipient` checks SAML 2.0 Profiles section 4.1.4.3 requires.
    --
    -- PER CONNECTION, and that is what identifies the connection a response arrived for.
    --
    -- Resolving instead by the response's `Issuer` cannot work, and the configuration that breaks
    -- it is ordinary: a customer with two organizations in this environment signs both into their
    -- ONE identity provider tenant, so both connections carry the same `idp_entity_id` and an
    -- issuer lookup has two rows and no basis for choosing. Making the issuer unique per
    -- environment would refuse that customer instead, which is not a fix.
    --
    -- So each connection publishes its own ACS URL, an operator pastes it into their identity
    -- provider, and the connection id is in the path. The `Issuer` is then CHECKED against the
    -- resolved connection, which is stronger than looking one up by it.
    acs_url                  text        NOT NULL,

    -- IDP-INITIATED SIGN-IN IS OFF, and this is the CVE-2026-9098 class.
    --
    -- An unsolicited response is one with no `InResponseTo`, so nothing ties it to a request this
    -- deployment issued: anyone who can obtain a signed assertion can replay it at the ACS. The
    -- profile permits it and most deployments do not need it, so it is opt in, and opting in
    -- turns on the replay cache below and the short validity bound beside it.
    allow_unsolicited        boolean     NOT NULL DEFAULT false,

    -- The tolerance applied to `NotBefore` and `NotOnOrAfter` (CVE-2026-9096 class). Small, and
    -- bounded here rather than only at the surface, because a large skew is indistinguishable
    -- from no time bound at all.
    clock_skew_secs          integer     NOT NULL DEFAULT 30
                                         CHECK (clock_skew_secs BETWEEN 0 AND 300),
    -- The longest an assertion may be valid for, whatever the identity provider asserted. It
    -- bounds how long a replay window is for an unsolicited response, and it bounds how long the
    -- replay cache below has to remember one.
    max_assertion_age_secs   integer     NOT NULL DEFAULT 300
                                         CHECK (max_assertion_age_secs BETWEEN 30 AND 3600),

    -- Which `NameID` format this connection expects, and how assertion attributes become identity
    -- traits. The mapping is the SAME shape the OIDC claim mapping uses, so an operator who has
    -- configured one has configured both.
    nameid_format            text        NOT NULL
                                         DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping        jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- Whether this connection requires the assertion to be encrypted. Off by default: signing is
    -- what makes an assertion trustworthy, encryption is what keeps it private in transit, and
    -- the transport is already TLS.
    require_encrypted_assertion boolean  NOT NULL DEFAULT false,

    active                   boolean     NOT NULL DEFAULT true,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT saml_connections_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT saml_connections_display_name_bounded
        CHECK (display_name <> '' AND octet_length(display_name) <= 252),
    -- BOUNDED IN BYTES, matching the surface, which counts `len()`. Two bounds on one value that
    -- disagree on the unit leave one unreachable and the other producing a 500.
    --
    -- An entity id is a URI by convention and is not required to be one, so it is bounded and not
    -- otherwise shaped here; the surface decides what it will accept.
    CONSTRAINT saml_connections_idp_entity_id_bounded
        CHECK (idp_entity_id <> '' AND octet_length(idp_entity_id) <= 1024),
    CONSTRAINT saml_connections_sp_entity_id_bounded
        CHECK (sp_entity_id <> '' AND octet_length(sp_entity_id) <= 1024),
    CONSTRAINT saml_connections_idp_sso_url_bounded
        CHECK (idp_sso_url <> '' AND octet_length(idp_sso_url) <= 2048),
    CONSTRAINT saml_connections_acs_url_bounded
        CHECK (acs_url <> '' AND octet_length(acs_url) <= 2048),
    CONSTRAINT saml_connections_nameid_format_bounded
        CHECK (nameid_format <> '' AND octet_length(nameid_format) <= 256),
    CONSTRAINT saml_connections_attribute_mapping_object
        CHECK (jsonb_typeof(attribute_mapping) = 'object'),

    -- ONE CONNECTION PER IDENTITY PROVIDER PER ORGANIZATION. Two connections in one organization
    -- pinning the same `idp_entity_id` would make "which connection asserted this" ambiguous at
    -- the ACS, and the ACS resolves a response by its `Issuer`.
    CONSTRAINT saml_connections_one_per_idp
        UNIQUE (tenant_id, environment_id, organization_id, idp_entity_id),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization must EXIST, and that is all this key does: referential integrity BYPASSES
    -- row-level security, so an id-only key admits any globally existing organization. What
    -- refuses a cross-scope one is the repository, which takes a scope-checked id. Identical to
    -- 0183 and 0189, and for the same reason: `organizations` carries no
    -- `UNIQUE (id, tenant_id, environment_id)` to reference.
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The management listing: every connection for one organization, oldest first, paged on the sort
-- columns. Without the pair in the index the filter is served and the sort is a heap sort.
CREATE INDEX saml_connections_by_org
    ON saml_connections (tenant_id, environment_id, organization_id, created_at, id);

-- NO INDEX ON `idp_entity_id`. The ACS resolves a connection by its own id, which the primary
-- key already serves; nothing queries by issuer, and an index for a query nothing issues is a
-- write cost nobody can account for. The UNIQUE constraint above still indexes it as its leading
-- columns allow, which is what the create's conflict check needs.

ALTER TABLE saml_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_connections_scope ON saml_connections
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle: pinning a trust anchor is an operator action, and one
-- that decides who may assert an identity in this environment.
--
-- UPDATE IS COLUMN SCOPED, and to the two columns the one UPDATE statement writes.
--
-- `set_active` is the operator's switch, and it exists in this slice because the ACS's issuer
-- lookup FILTERS ON `active`: a column a query reads and nothing can write is a filter that can
-- never be false, which is a defence in the shape of a comment. The switch and the filter arrive
-- together or neither should.
--
-- The other columns are not here. Nothing edits a connection in place, so a connection an
-- operator audited stays the connection they audited: re-pointing one at a different identity
-- provider means deleting it and creating another, which mints a new id and writes two audit
-- rows with two actions rather than one row saying it was edited.
GRANT SELECT, INSERT, DELETE ON saml_connections TO ironauth_control;
GRANT UPDATE (active, updated_at) ON saml_connections TO ironauth_control;

-- The DATA plane READS. The ACS runs there: it resolves the connection by issuer, reads the
-- pinned keys, and validates. It writes nothing here.
GRANT SELECT ON saml_connections TO ironauth_app;
