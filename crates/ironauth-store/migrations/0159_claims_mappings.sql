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
    -- ONE constraint for the whole document shape, not two ordered ones.
    --
    -- The first version had a separate array check and a separate length check, and the array
    -- check could never fire: Postgres evaluates CHECKs in constraint-NAME order, and
    -- `jsonb_array_length` RAISES 22023 on a non-array rather than returning false, so whichever
    -- of the two sorted first decided every case. Renaming them to fix the ordering left the fix
    -- resting on alphabetical luck, which nothing measures and the next rename quietly breaks.
    --
    -- A CASE removes the dependence: the type test guards the length test in one expression, so
    -- a non-array, a scalar and a JSON null are all plain check violations naming this
    -- constraint, and a 33-element array is the same violation for the other reason.
    --
    -- Thirty-two matches OIDC_MAX_ENRICHED_CLAIMS, the ceiling the enrichment hook's allowlist
    -- already carries, because both answer the same question: how many claims may one mechanism
    -- contribute to a token. This is read on every issuance for the client, so an unbounded rule
    -- list is an unbounded cost on the login path.
    CONSTRAINT claims_mappings_rules_shape
        CHECK (
            CASE
                WHEN jsonb_typeof(rules) = 'array' THEN jsonb_array_length(rules) <= 32
                ELSE false
            END
        )
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

-- NO data-plane grant yet. The issuance path WILL read these on every token it mints, and that
-- reader does not exist: its only exerciser today would be a test, and the rule this file states
-- for DELETE applies just as much to SELECT -- "a privilege held by nobody is one an attacker
-- inherits for free". It arrives with the mint-side reader.
--
-- When it does, the split is SELECT for the data plane and nothing more: the plane that mints
-- tokens must not be able to change the shape of the tokens it mints, which is the same
-- separation `messages` draws.

-- The CONTROL plane is where an operator writes a mapping: `ActingClaimsMappingRepo::set`,
-- audited as `claims_mapping.set`. The grants arrive WITH that caller rather than ahead of it,
-- which is the rule this file states for DELETE and which the first version of these grants
-- broke: it took INSERT and UPDATE and named a snapshot import as their caller, which the same
-- change disproves, since both promoted projections for this type are empty by construction.
--
-- No DELETE. Removing a client's mapping is an ordinary operation this table will need, and the
-- operation does not exist yet; a privilege held by nobody is one an attacker inherits for free.
GRANT SELECT, INSERT, UPDATE ON claims_mappings TO ironauth_control;
