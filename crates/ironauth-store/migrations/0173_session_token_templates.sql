-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The SESSION TOKENIZER templates and their own signing keys. Issue #119.
--
-- A tokenizer template converts a valid opaque DB-backed session into a short-lived JWT: a
-- named, per-environment configuration object carrying an audience, a TTL bound, a claims
-- mapper, and ITS OWN key set published at its own JWKS URL. The point of the whole feature is
-- that the consumer of the minted token -- a service mesh, a third-party API, an edge worker --
-- verifies it with NO database call, so everything the verifier needs has to be reachable from
-- a published JWKS and the token itself.
--
-- # Why the keys are a SEPARATE TABLE and not rows in `signing_keys`
--
-- This is the decision in this file that carries a security consequence, so it is written down
-- rather than assumed.
--
-- `SigningKeyRepo::list` returns EVERY signing key in a scope, and the environment's published
-- JWKS is built from exactly that list. A `key_set` column on `signing_keys` would therefore
-- make the environment's own JWKS publish every template's key too, unless every existing
-- reader grew a filter it does not have today. That is a filter each future reader has to
-- remember, and the failure when one forgets is not a broken build: it is an ID token verifying
-- against a tokenizer template's key, and a tokenized session JWT verifying against the
-- issuer's. Cross-profile key confusion is precisely what a separate key set is FOR, so
-- reaching it by a forgotten `WHERE` would defeat the feature quietly.
--
-- A separate table makes the separation structural. No existing query can see these rows,
-- because no existing query names this table. The cost is that rotation choreography is not
-- shared, and this migration is honest about that: the lifecycle columns below are the SAME
-- four instants `signing_keys` carries, so the rotation logic can be lifted onto them when a
-- rotation surface for templates is built. What ships here is one active key per template,
-- created with the template.
--
-- # Why EdDSA only
--
-- Every other signing surface in this system admits four algorithm families because it has to:
-- an OAuth client, a federation peer, or a resource server may require RS256 and IronAuth does
-- not get to choose their verifier. A tokenizer template has no such constraint -- the
-- template, its key, its audience and its consumers are all configured by the same operator at
-- the same time -- so this table admits ONE algorithm and one material kind, and the CHECKs say
-- so rather than leaving a matrix the loader has to reject at mint time.
--
-- EdDSA specifically because it is what the shipped verifier can verify: the WebCrypto
-- TypeScript core maps `EdDSA` onto WebCrypto's `Ed25519`, so a template minted here verifies
-- in the SDK, in an edge runtime, and in a browser with no extra dependency. Ed25519 is also
-- what makes per-template key sets cheap enough to be the default rather than a luxury: a
-- 32-byte seed and no parameter generation.
--
-- # Key material is stored the way `signing_keys` stores it
--
-- Unwrapped bytes, exactly as migration 0005 stores an issuer's key material, and NOT under the
-- 0028 envelope. That is deliberate consistency rather than an oversight: 0028's envelope seals
-- PII and named secrets, and no signing key in this system has ever been inside it. Putting one
-- class of signing key under the envelope and leaving the other outside would mean two answers
-- to "where do signing keys live" and a reader who checks the wrong one. If signing keys move
-- under the envelope, both tables move together.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table ENABLEs and FORCEs
-- row-level security, adds the (tenant, environment) isolation policy, adds the nonempty-scope
-- CHECK, and declares the scope foreign keys directly. Both tables below do all four. Every
-- statement is additive, so this migration is an EXPAND.

CREATE TABLE session_token_templates (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The name the tokenize request selects this template by (`tokenize_as`). Like a challenge
    -- component's name this is a CONFIGURATION CONTRACT rather than a label: it appears in the
    -- caller's request and in the template's JWKS URL, so renaming one breaks both.
    name            text        NOT NULL,
    -- The `aud` every token minted from this template carries. RFC 8725 section 3.9 asks for an
    -- audience restriction on every token, and a template with no audience would mint a token
    -- every verifier in the estate accepts -- which is the confused-deputy shape the per-
    -- template key set exists to prevent, reached through the claim set instead of the key.
    audience        text        NOT NULL,
    -- How long a minted token lives, in seconds.
    --
    -- The BOUND IS THE FEATURE, not a guard rail on it. A tokenized session JWT is verified
    -- with no database call, so the underlying session's revocation cannot reach a token that
    -- is already minted: revocation takes effect at the next MINT. This number is therefore the
    -- exact width of the window in which a revoked session's token still verifies, which is why
    -- the docs state the revocation window as a function of it and why it is capped here rather
    -- than left to configuration.
    --
    -- Fifteen minutes is the ceiling and thirty seconds the floor. The floor exists because a
    -- TTL shorter than the clock skew a verifier tolerates is a token that is expired on
    -- arrival for some verifiers and not others, which reads as an intermittent outage.
    ttl_seconds     integer     NOT NULL,
    -- The claims mapper, as the JSON encoding of `Vec<MappingRule>`: the SAME rule vocabulary
    -- `claims_mappings.rules` carries and the same validator refuses protected claims with.
    --
    -- One wire format and one validator, deliberately. A second rule shape defined for this
    -- feature would be a second answer to "may a mapping write `sub`", and the first time those
    -- two answers differed one of them would be wrong in production.
    rules           jsonb       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),

    CONSTRAINT session_token_templates_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Sixty-four characters, matching the token hook and challenge component name bound, so an
    -- operator learns one rule rather than three.
    CONSTRAINT session_token_templates_name_bounded
        CHECK (name <> '' AND length(name) <= 64),
    CONSTRAINT session_token_templates_audience_bounded
        CHECK (audience <> '' AND length(audience) <= 255),
    CONSTRAINT session_token_templates_ttl_bounded
        CHECK (ttl_seconds >= 30 AND ttl_seconds <= 900),
    -- A rule list, and a BOUNDED one.
    --
    -- The count bound is here as a BACKSTOP and not as the first refusal, which is the
    -- correction to what `claims_mappings` shipped. Its own module header records the gap:
    -- "a thirty-three-rule document passes `validate` and is refused by the table's CHECK
    -- constraint, which surfaces as a 500 rather than an audited 400". The write path for this
    -- table counts the rules itself and returns a 400 naming the bound, so an operator never
    -- reaches this constraint by ordinary use. It stays because a constraint nobody reaches is
    -- still what stands between a hand-edited row and an unbounded read on the mint path.
    CONSTRAINT session_token_templates_rules_bounded
        CHECK (jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) <= 32)
);

ALTER TABLE session_token_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_token_templates FORCE ROW LEVEL SECURITY;

CREATE POLICY session_token_templates_scope ON session_token_templates
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle, for the reason `claims_mappings` gives: a data plane
-- that could write itself a template and then mint from it is a privilege escalation with no
-- audit trail. Here it is sharper still, because a template names its own audience.
GRANT SELECT, INSERT, UPDATE, DELETE ON session_token_templates TO ironauth_control;

-- And the DATA plane READS it, because the tokenize endpoint is what mints from it.
GRANT SELECT ON session_token_templates TO ironauth_app;

-- One template's own signing keys: the key set its JWKS publishes and its tokens are signed by.
CREATE TABLE session_token_template_keys (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The template this key belongs to.
    template_name   text        NOT NULL,
    -- The `stk_` scoped identifier, which is also the JOSE `kid` of every token this key signs.
    id              text        PRIMARY KEY,
    -- Declared and CONSTRAINED to one value each rather than left open. See the header.
    algorithm       text        NOT NULL,
    material_kind   text        NOT NULL,
    key_material    bytea       NOT NULL,
    -- The same four lifecycle instants `signing_keys` carries, from the application clock seam
    -- and never the database clock, so a rotation surface for templates has somewhere to land
    -- without a second migration reshaping this table.
    publish_at      timestamptz NOT NULL,
    activate_at     timestamptz NOT NULL,
    retire_at       timestamptz,
    expire_at       timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),

    -- THE SCOPE KEYS, DECLARED DIRECTLY, even though the composite key below reaches a row that
    -- has them. `every_scoped_table_declares_a_scope_foreign_key` requires it of every table
    -- with forced RLS, and it is right to: transitive anchoring survives only as long as nobody
    -- relaxes an intermediate key.
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- CASCADE, so deleting a template takes its keys with it. A key that outlived its template
    -- would keep a JWKS URL answering for a template that no longer exists, and a later
    -- template of the same name would inherit a key set nobody granted it.
    FOREIGN KEY (tenant_id, environment_id, template_name)
        REFERENCES session_token_templates (tenant_id, environment_id, name) ON DELETE CASCADE,

    CONSTRAINT session_token_template_keys_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT session_token_template_keys_algorithm_eddsa
        CHECK (algorithm = 'EdDSA'),
    CONSTRAINT session_token_template_keys_material_ed25519
        CHECK (material_kind = 'ed25519_seed' AND octet_length(key_material) = 32)
);

CREATE INDEX session_token_template_keys_template_idx
    ON session_token_template_keys (tenant_id, environment_id, template_name);

ALTER TABLE session_token_template_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_token_template_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY session_token_template_keys_scope ON session_token_template_keys
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The control plane MINTS the key when the template is created, and reads it back to report the
-- template. No UPDATE and no DELETE: there is no rotation surface yet, so those would be
-- standing capabilities with no caller, which is exactly what 0106 and 0108 revoked elsewhere.
-- DELETE of a key happens through the template's ON DELETE CASCADE, which needs no grant.
GRANT SELECT, INSERT ON session_token_template_keys TO ironauth_control;

-- The DATA plane reads the key to sign with it and to publish the template's JWKS. SELECT only.
GRANT SELECT ON session_token_template_keys TO ironauth_app;
