-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The key this deployment signs its OWN SAML messages with (issue #139).
--
-- Every SAML key that existed before this migration belonged to somebody else: 0197 pins the
-- certificates an identity provider publishes, and pinning them is a statement about whose
-- assertions this deployment will believe. This table is the other direction. #139 requires
-- AuthnRequests "signed by default", and a signature needs a private key that is ours.
--
-- PER CONNECTION, NOT PER ENVIRONMENT, and that follows from 0196 rather than being a fresh
-- choice: `sp_entity_id` is a per-connection column, so this deployment already presents a
-- DIFFERENT service-provider identity to each customer's identity provider. One key across all
-- of them would make a single compromise a signature that every customer's IdP accepts, and it
-- would make rotating for one customer a rotation for all of them.
--
-- THE PUBLIC HALF IS NOT STORED. It is derivable from the private key, and a stored copy is a
-- second answer to "what is this connection's public key" that can drift from the first. What
-- publishes it is the SP metadata document, which derives it at render time.

CREATE TABLE saml_sp_signing_keys (
    -- The `sps_` scoped identifier.
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The connection this key signs for. ON DELETE CASCADE, unlike 0197's pinned certificates,
    -- which have no cascade: a pinned certificate is a record of a trust decision and outlives
    -- the connection for audit, while a private key whose connection is gone is a credential
    -- nobody can use and nobody should still be holding.
    connection_id     text        NOT NULL,

    -- The signature algorithm this key produces, as the SAML/XML-Signature URI fragment rather
    -- than a JOSE name: `rsa-sha256`. Spelled here because an operator reading the row and an
    -- operator reading their identity provider's configuration should see the same word, and
    -- because the redirect binding puts this value on the wire as `SigAlg`.
    --
    -- RSA AND NOT AN ELLIPTIC CURVE, which is a deliberate interoperability choice rather than a
    -- preference: RFC 4051 defines ECDSA URIs and the SAML profiles permit them, and Okta, Entra
    -- and ADFS in practice verify `rsa-sha256`. A key nobody accepts signs nothing.
    algorithm         text        NOT NULL,

    -- The private key in PKCS#1 DER, which is the encoding `ironauth-jose` already generates RSA
    -- keys in and loads them back from. Mirrors `signing_keys` (0005), the table this one is a
    -- sibling of: the same at-rest protection, and the same rule that the material never leaves
    -- the store layer except inside an opaque newtype that redacts on `Debug`.
    key_material      bytea       NOT NULL,

    -- The lifecycle instants, from the application clock seam and never `now()`, for the reason
    -- 0198 gives at length: a default here would be the database's clock deciding a bound the
    -- application is also computing, and the two disagree under load.
    --
    -- `retired_at` is NULL while this is the key the connection signs with. A rotation writes a
    -- successor and stamps this, so a verifier that cached the old public key during the
    -- changeover has a window in which BOTH are published by the metadata document.
    created_at        timestamptz NOT NULL,
    retired_at        timestamptz,

    CONSTRAINT saml_sp_signing_keys_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT saml_sp_signing_keys_algorithm_known
        CHECK (algorithm IN ('rsa-sha256')),
    -- A 2048-bit RSA private key in PKCS#1 is about 1.2 KiB and a 4096-bit one about 2.4 KiB.
    -- The floor is what makes an empty or truncated write a database error rather than a
    -- signature failure at the first sign-in.
    CONSTRAINT saml_sp_signing_keys_material_bounded
        CHECK (octet_length(key_material) BETWEEN 512 AND 8192),
    CONSTRAINT saml_sp_signing_keys_retired_after_created
        CHECK (retired_at IS NULL OR retired_at > created_at),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (connection_id) REFERENCES saml_connections (id) ON DELETE CASCADE
);

CREATE INDEX saml_sp_signing_keys_connection_idx
    ON saml_sp_signing_keys (tenant_id, environment_id, connection_id);

-- ONE LIVE KEY PER CONNECTION, enforced rather than assumed. "Which key does this connection
-- sign with" must have one answer: with two, the AuthnRequest is signed by whichever the plan
-- returned first while the metadata document publishes both, and a verifier that picked the
-- other one refuses every request. A rotation retires the incumbent in the same transaction
-- that writes the successor, so the partial index is never violated in between.
CREATE UNIQUE INDEX saml_sp_signing_keys_one_live
    ON saml_sp_signing_keys (tenant_id, environment_id, connection_id)
    WHERE retired_at IS NULL;

ALTER TABLE saml_sp_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_sp_signing_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_sp_signing_keys_scope ON saml_sp_signing_keys
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE CONTROL PLANE MINTS AND RETIRES; THE DATA PLANE READS. Provisioning a key is an operator
-- action with a lasting consequence -- the metadata an operator uploads to their identity
-- provider is derived from it -- so it goes through `ScopedStore::acting` and its audit trail,
-- exactly as pinning a certificate does in 0197. Signing an AuthnRequest happens on a sign-in,
-- which runs on the data plane, and needs nothing but a read.
GRANT SELECT, INSERT, UPDATE ON saml_sp_signing_keys TO ironauth_control;

-- SELECT ALONE FOR THE APP ROLE, and the absence of the others is the point. The endpoint that
-- signs an AuthnRequest has no reason to mint a key, and a compromise of the data-plane role
-- must not be able to write one it controls: a key it minted would be a key it could sign
-- another deployment's requests with, published as ours by our own metadata.
GRANT SELECT ON saml_sp_signing_keys TO ironauth_app;
