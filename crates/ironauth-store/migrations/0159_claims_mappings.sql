-- Declarative claim mappings (issue #113 criterion 4).
--
-- "Declarative mappings cover renames, group filtering, static claims, and ID-versus-access-
-- token placement with no custom code, and promote via config snapshots."
--
-- The rules themselves already exist, pure and tested, in `ironauth-oidc::claims_mapping`:
-- `MappingRule::{Rename, Static, FilterList, Place}` plus a `validate` that refuses a rule
-- writing a reserved claim. What was missing was somewhere for an operator to WRITE them.
--
-- # Why a table and not a config section
--
-- The criterion ends with "promote via config snapshots", and in this codebase that phrase has
-- a precise meaning: `snapshot.rs` carries per-resource projections of STORED tables that
-- `classification::classify` marks Promotable, and a test binds `SNAPSHOT_RESOURCE_TYPES` to
-- exactly that set. Process configuration does not promote -- the `OidcConfig` fields that
-- mention snapshots say so themselves, calling the process value "the deployment default until
-- per-environment overrides land". A `[oidc.claims_mapping]` section would have satisfied the
-- first half of the criterion and quietly failed the second.
--
-- # Per client, because that is the unit the decision is made for
--
-- The `token.customize` contract identifies the client in every invocation precisely so one
-- integration can behave differently per client, and mappings are the declarative half of the
-- same feature: they apply first, and the hook then refines the result. An environment-wide
-- mapping would force every client's tokens to carry the same shape, which is the thing an
-- operator reaches for a mapping to avoid. The natural key is the client id, the same key
-- `ClientSnapshot` promotes under.
--
-- # The rules are one JSONB document, not a row per rule
--
-- They are validated, applied, and refused AS A LIST: `validate` rejects the whole set if any
-- rule names a reserved claim, deliberately, so an operator never gets a half-applied mapping.
-- A row per rule would make the ordinal a thing two writers could disagree about and would let
-- a partial write leave a rule set that was never validated as a whole. The shape inside is
-- checked in Rust at write time against the same `validate` the issuance path uses, so there is
-- one fence rather than a SQL CHECK that would be a second, weaker copy of it.
CREATE TABLE claims_mappings (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The OAuth client these rules shape tokens for. Not a foreign key to `clients`: a
    -- snapshot is imported into a target environment where the client row may not exist yet,
    -- and an import that ordered resources by referential dependency would be a second
    -- ordering to get wrong. The mapping is inert until a client of that id issues a token.
    client_id       text        NOT NULL,
    -- The ordered rule list, as the JSON encoding of `Vec<MappingRule>`.
    rules           jsonb       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, client_id),

    CONSTRAINT claims_mappings_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT claims_mappings_client_nonempty
        CHECK (client_id <> ''),
    -- An ARRAY, which is the one structural fact SQL can decide about this document without
    -- becoming a second copy of `validate`. A rule set that is not a list is not a rule set,
    -- and catching that here means a malformed write cannot become a decode failure on the
    -- issuance path.
    CONSTRAINT claims_mappings_rules_is_array
        CHECK (jsonb_typeof(rules) = 'array'),
    -- A bound on the document, for the reason the hook response has one: this is read on every
    -- token issuance for the client, and an unbounded rule list is an unbounded cost on the
    -- login path. Thirty-two matches OIDC_MAX_ENRICHED_CLAIMS, the ceiling the enrichment
    -- hook's allowlist already carries, because both answer the same question: how many claims
    -- may one mechanism contribute to a token.
    CONSTRAINT claims_mappings_rules_bounded
        CHECK (jsonb_array_length(rules) <= 32)
);

ALTER TABLE claims_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE claims_mappings FORCE ROW LEVEL SECURITY;

CREATE POLICY claims_mappings_scope ON claims_mappings
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane READS the rules on the issuance path and never writes them. A mapping is
-- configuration: the plane that mints tokens must not be able to change the shape of the
-- tokens it mints, which is the same separation `messages` draws when it gives the control
-- plane SELECT only.
GRANT SELECT ON claims_mappings TO ironauth_app;

-- The CONTROL plane is where an operator writes a mapping, and where a snapshot import applies
-- one. No DELETE grant: removing a client's mapping is an ordinary operation this table will
-- need, but the operation does not exist yet, and a privilege held by nobody is one an attacker
-- inherits for free. It arrives with its caller.
GRANT SELECT, INSERT, UPDATE ON claims_mappings TO ironauth_control;
