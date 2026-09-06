-- A SAML binding may only name a connection its OWN organization owns (issue #139).
--
-- WHAT WENT WRONG, IN TWO STEPS, AND WHY THE FIX BELONGS HERE. Migration 0201 let an org
-- connection name a SAML connection, and nothing tied the binding's `organization_id` to the
-- connection's. So a binding in organization A could name a connection owned by B, and the two
-- attempts to cope with that in the READ each broke differently:
--
--   * Resolving by connection alone matched BOTH organizations' bindings and kept whichever the
--     planner yielded, stamping a user with a binding from an organization they are not a member
--     of -- so that organization's broker overlay applied and the routed one's did not.
--   * Constraining the read to the CONNECTION'S OWN organization then resolved the wrong side of
--     the pairing: the binding whose overlay an operator configured is the one the ROUTING RULE
--     matched, and when that binding sits in a different organization than the connection's
--     owner the read finds nothing at all. An `overlay_min_acr = mfa` floor set on the very
--     binding that routed the login was silently dropped -- an enforced floor turned into an
--     unenforced one by the change meant to harden it.
--
-- BOTH FAILURES ARE THE SAME MISSING FACT: the schema permitted a pairing that has no meaning. A
-- SAML connection names one organization's people by its own NOT NULL column; a binding in a
-- different organization pointing at it is not a policy an operator can have intended, and every
-- reader downstream has to guess which of the two organizations it is really about. So the
-- pairing is refused where it is written rather than interpreted where it is read, and the
-- connection's organization and the binding's are then the same organization by construction --
-- which makes the reader's question well-posed instead of merely answered.
--
-- A SUPERKEY, BECAUSE A FOREIGN KEY NEEDS ONE. `saml_connections.id` is already the primary key,
-- so `(tenant_id, environment_id, organization_id, id)` is unique for free; declaring it is what
-- lets the composite reference below exist. It adds no restriction of its own.
ALTER TABLE saml_connections
    ADD CONSTRAINT saml_connections_org_scoped_key
    UNIQUE (tenant_id, environment_id, organization_id, id);

-- MATCH SIMPLE IS THE DEFAULT AND IT IS WHAT MAKES THIS SAFE FOR CONNECTOR BINDINGS: when any
-- referencing column is NULL the constraint is not checked, and `saml_connection_id` is NULL for
-- every binding that names a connector. So this constrains SAML bindings and leaves the OIDC
-- ones exactly as they were.
--
-- NO EXISTING ROW CAN VIOLATE IT. The column arrived in 0201, one migration ago, and no shipped
-- surface writes it -- there is no management route, OpenAPI path or CLI verb that creates a SAML
-- binding -- so every `saml_connection_id` in any deployed database is NULL and the constraint
-- validates instantly.
ALTER TABLE org_connections
    ADD CONSTRAINT org_connections_saml_same_organization
    FOREIGN KEY (tenant_id, environment_id, organization_id, saml_connection_id)
    REFERENCES saml_connections (tenant_id, environment_id, organization_id, id);

COMMENT ON CONSTRAINT org_connections_saml_same_organization ON org_connections IS
    'A binding may only name a SAML connection owned by the same organization; the read that '
    'resolves a routed binding relies on this rather than choosing between two organizations '
    '(issue #139).';
