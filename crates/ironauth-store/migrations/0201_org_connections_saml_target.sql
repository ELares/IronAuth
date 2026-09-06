-- An organization binding whose upstream is a SAML connection (issue #139, criterion 5).
--
-- WHAT IT CLOSES. Domain-based home-realm discovery resolves a routing rule to an `ocn_` binding
-- and follows it to an upstream, and until now an upstream could only be a `cnr_` OIDC connector.
-- So a customer whose identity provider speaks SAML could be signed in -- the assertion consumer
-- and the start endpoint both ship -- but never ROUTED: typing an email at the login page found
-- no rule that could name their connection, and the operator's only option was to hand every
-- user a deep link. #139 asks for SAML connections to "participate in domain-based discovery
-- routing identically to OIDC connections", and this is the column that lets a rule point at one.
--
-- EXACTLY ONE UPSTREAM, ENFORCED IN THE SCHEMA. A binding names a connector or a SAML connection
-- and never both, because "both" has no meaning: the two are different protocols with different
-- redirect targets, and a reader that had to choose would be choosing on behalf of an operator
-- who did not say. The CHECK is what makes the Rust reader's two-arm match total rather than
-- hopeful.
--
-- WHY `connector_id` CAN BE RELAXED SAFELY. Dropping NOT NULL from a column an older binary
-- decodes as non-null is normally how a rolling upgrade breaks: the old reader meets a NULL it
-- has no arm for. It is safe HERE because a NULL can only appear in a row a NEW binary wrote,
-- and only a new binary can write one: the column is only ever NULL when `saml_connection_id` is
-- set, there is no management surface that sets it before this release, and every existing row
-- keeps its value. An old replica reading rows it or its peers already wrote sees exactly what
-- it saw before.
ALTER TABLE org_connections
    ADD COLUMN saml_connection_id text;

ALTER TABLE org_connections
    ALTER COLUMN connector_id DROP NOT NULL;

ALTER TABLE org_connections
    ADD CONSTRAINT org_connections_one_upstream
    CHECK (num_nonnulls(connector_id, saml_connection_id) = 1);

-- ONE ORGANIZATION MAPS A GIVEN SAML CONNECTION AT MOST ONCE, which is the mirror of the
-- connector index beside it. Partial, because a row with no `saml_connection_id` is an OIDC
-- binding and several of those in one organization are ordinary.
CREATE UNIQUE INDEX org_connections_org_saml_idx
    ON org_connections (tenant_id, environment_id, organization_id, saml_connection_id)
    WHERE saml_connection_id IS NOT NULL;

-- THE EXISTING CONNECTOR INDEX BECOMES PARTIAL TOO. Postgres treats NULLs as distinct in a
-- unique index, so several SAML bindings in one organization would each carry a NULL
-- `connector_id` and not collide -- which is the behaviour wanted, but by accident rather than
-- by statement. Saying `WHERE connector_id IS NOT NULL` makes the index mean "at most one
-- binding per connector" rather than "at most one per connector, and NULLs do whatever NULLs
-- do".
DROP INDEX org_connections_org_connector_idx;
CREATE UNIQUE INDEX org_connections_org_connector_idx
    ON org_connections (tenant_id, environment_id, organization_id, connector_id)
    WHERE connector_id IS NOT NULL;

COMMENT ON COLUMN org_connections.saml_connection_id IS
    'The smc_ SAML connection this binding routes to, or NULL for a cnr_ connector binding. '
    'Exactly one of the two is set (issue #139).';
