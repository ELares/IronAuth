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
-- a partial write leave a rule set that was never validated as a whole. What a rule may TARGET
-- is checked in Rust at write time against the same `validate` the issuance path uses, so the
-- reserved-claim rule has one fence rather than a weaker SQL copy of it.
--
-- The COUNT is a different question and has three checks, deliberately: `validate` carries no
-- count bound at all, so a 33-rule document passes it, is refused by the CHECK below, and is
-- refused again by the snapshot import validator. Not one fence duplicated -- three checks of
-- three different things, at the three places a rule set can arrive.
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
    -- The SCOPE keys, which every sibling declares and this table was missing. Their absence is
    -- not cosmetic: `error::is_absent_scope` turns a write into a non-existent scope into a
    -- uniform not-found by matching SQLSTATE 23503 on a `_tenant_id_fkey` constraint, so with
    -- no key there is no 23503, nothing converts, and the write LANDS as an orphan row in an
    -- environment that does not exist.
    --
    -- The header's argument for having no key onto `clients` (a snapshot import may arrive
    -- before the client row) does not extend to these: the target scope exists by definition,
    -- because the import is being applied INTO it.
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),

    CONSTRAINT claims_mappings_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT claims_mappings_client_nonempty
        CHECK (client_id <> ''),
    -- An ARRAY, which is the one structural fact SQL can decide about this document without
    -- becoming a second copy of `validate`. A rule set that is not a list is not a rule set,
    -- and catching that here means a malformed write cannot become a decode failure on the
    -- issuance path.
    --
    -- NAMED to sort FIRST, deliberately. Postgres evaluates CHECK constraints in constraint-NAME
    -- order, and the length check below RAISES 22023 on a non-array rather than returning false.
    -- Named the obvious way, this constraint could never fire for any value: dropping it
    -- entirely produced byte-identical errors. The `_a_`/`_b_` infixes are what make the
    -- structural check the one that answers.
    CONSTRAINT claims_mappings_rules_a_is_array
        CHECK (jsonb_typeof(rules) = 'array'),
    -- A bound on the document, for the reason the hook response has one: this is read on every
    -- token issuance for the client, and an unbounded rule list is an unbounded cost on the
    -- login path. Thirty-two matches OIDC_MAX_ENRICHED_CLAIMS, the ceiling the enrichment
    -- hook's allowlist already carries, because both answer the same question: how many claims
    -- may one mechanism contribute to a token.
    --
    -- Named to sort AFTER the structural check above, so a non-array is refused as a non-array
    -- rather than raising 22023 out of this one.
    CONSTRAINT claims_mappings_rules_b_bounded
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

-- The CONTROL plane is where an operator writes a mapping: `ActingClaimsMappingRepo::set`,
-- audited as `claims_mapping.set`. The grants arrive WITH that caller rather than ahead of it,
-- which is the rule this file states for DELETE and which the first version of these grants
-- broke: it took INSERT and UPDATE and named a snapshot import as their caller, which the same
-- change disproves, since both promoted projections for this type are empty by construction.
--
-- No DELETE. Removing a client's mapping is an ordinary operation this table will need, and the
-- operation does not exist yet; a privilege held by nobody is one an attacker inherits for free.
GRANT SELECT, INSERT, UPDATE ON claims_mappings TO ironauth_control;
