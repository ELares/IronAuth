-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-environment signing keys (issue #19).
--
-- Issuer and key isolation is blast-radius engineering: one tenant's key
-- compromise or botched rotation must not cross a tenant or environment line.
-- This is the persistence half of that guarantee. Every signing key is a
-- tenant-scoped row, isolated exactly like `clients`: mandatory tenant_id and
-- environment_id, the nonempty-scope CHECK, forced row-level security keyed on
-- the same transaction-local session variables, and the same isolation-preserving
-- foreign keys. A key row is reachable ONLY through the data-plane scoped
-- repository (ironauth_app) bound to one (tenant, environment), so the signing
-- core's key lookup structurally cannot express a cross-tenant read: there is no
-- query shape that returns another tenant's key material.
--
-- The row `id` is a `sik_` scoped identifier that embeds its (tenant, environment)
-- in the clear and carries a non-recyclable 128-bit random unique component. That
-- id doubles as the JOSE `kid`, so a `kid` is unique across an issuer's whole key
-- history by construction (it is the table's PRIMARY KEY) and can never be reused
-- after a key is retired.
--
-- Key material at rest: this migration stores the PRIVATE key material in
-- `key_material` (an Ed25519 seed, an ECDSA PKCS#8 document, or an RSA PKCS#1 DER
-- document, distinguished by `material_kind`). At-rest envelope encryption, BYOK,
-- crypto-shredding, and external KMS/HSM signer backends are deliberately OUT OF
-- scope here (M5 and the #9 pluggable signer seam own them); this issue ships the
-- isolation and the rotation choreography only. The application never logs the
-- material (the record type redacts it in Debug), and the low-privilege app role
-- is the only grantee.
--
-- Rotation choreography lives in the application (ironauth-jose): the four
-- lifecycle instants below are written from the application clock seam, never the
-- database clock, so the pre-publish and retain rules are deterministic under a
-- manual clock in tests.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh.
-- signing_keys does all four.

CREATE TABLE signing_keys (
    -- The sik_ scoped identifier; also the JOSE kid on every JWS this key signs.
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The JOSE algorithm name this key signs and publishes with (EdDSA, ES256,
    -- ES384, RS256, RS384, RS512, PS256, PS384, PS512). Never an HS* value: the
    -- application key store has no symmetric key type.
    algorithm      text        NOT NULL,
    -- The private key material, and which encoding it is in.
    material_kind  text        NOT NULL,
    key_material   bytea       NOT NULL,
    -- The lifecycle instants (from the application clock seam). publish_at is when
    -- the key first appears in the published JWKS (pre-publication); activate_at is
    -- when it first signs; retire_at is when a successor took over (NULL while it
    -- is the current head); expire_at is when the last token it signed has expired
    -- and it is withdrawn from the JWKS (NULL while not retired).
    publish_at     timestamptz NOT NULL,
    activate_at    timestamptz NOT NULL,
    retire_at      timestamptz,
    expire_at      timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signing_keys_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX signing_keys_scope_idx ON signing_keys (tenant_id, environment_id);

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_tenant_isolation ON signing_keys
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to provision and read keys; UPDATE so a manual rotation can stamp
-- retire_at/expire_at on the outgoing key. No DELETE grant: a retired key's row is
-- retained (its kid must never be reused, and its lifecycle is rotation evidence).
GRANT SELECT, INSERT, UPDATE ON signing_keys TO ironauth_app;
