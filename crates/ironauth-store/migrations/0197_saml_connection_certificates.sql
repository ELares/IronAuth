-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The signing keys a SAML connection trusts (issue #139).
--
-- # Why the key and the certificate are both here
--
-- `ironauth-saml`'s verifier takes an `XmlSigKey`: a raw EC point, or an RSA modulus and
-- exponent. Not DER. That is a deliberate refusal to put an X.509 parser on the path of
-- attacker-adjacent bytes, and it is the property this table preserves.
--
-- So the parse happens ONCE, when an operator uploads a certificate or an IdP metadata document,
-- and both halves are stored. `public_key` is what the ACS hands the verifier and is the only
-- column on the assertion path. `certificate_der` is what an operator is shown, what a
-- fingerprint is computed from, and what `not_after` was read out of.
--
-- Storing the parsed key rather than re-parsing per assertion is also what makes the trust
-- decision auditable: the bytes that will verify a signature were fixed at the moment somebody
-- decided to trust them, and no later parser change can quietly reinterpret them.
--
-- # Many per connection, and any live one verifies
--
-- Certificate rotation is scheduled by the customer, not by this deployment. A connection that
-- could pin one key would break at every rotation, so an operator adds the new certificate
-- before the identity provider switches and removes the old one afterwards. The overlap window
-- is the rows that exist at the same time; issue #141 adds the expiry alerting and the renewal
-- flow that make it a product rather than an operation.

CREATE TABLE saml_connection_certificates (
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    connection_id       text        NOT NULL,

    -- THE VERIFIER'S INPUT. Raw key material in the encoding `XmlSigKey` names: for
    -- `ecdsa_p256` and `ecdsa_p384` the uncompressed point `0x04 || x || y`; for `rsa` the
    -- modulus, with the exponent beside it.
    key_kind            text        NOT NULL
                                    CHECK (key_kind IN ('ecdsa_p256', 'ecdsa_p384', 'rsa')),
    public_key          bytea       NOT NULL,
    -- The RSA public exponent. Absent for the EC kinds, and a CHECK below ties the two together
    -- so a row cannot claim `rsa` without one.
    rsa_exponent        bytea,

    -- THE OPERATOR'S VIEW. Never read on the assertion path.
    certificate_der     bytea       NOT NULL,
    -- The SHA-256 of `certificate_der`, which is how an operator confirms the pin matches what
    -- their identity provider published. Stored rather than computed on read so a listing does
    -- not hash every certificate it returns.
    fingerprint_sha256  bytea       NOT NULL,
    -- Read out of the certificate at upload. `not_after` is what #141's expiry alerting reads;
    -- it is NOT enforced here, deliberately -- see the paragraph below.
    not_before          timestamptz NOT NULL,
    not_after           timestamptz NOT NULL,

    created_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT saml_connection_certificates_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- SHAPED TO THE KIND. A row claiming `rsa` with no exponent, or an EC kind carrying one, is
    -- a row the verifier cannot be handed, and the failure would surface at sign-in rather than
    -- at upload.
    CONSTRAINT saml_connection_certificates_exponent_matches_kind
        CHECK (
            (key_kind = 'rsa' AND rsa_exponent IS NOT NULL AND octet_length(rsa_exponent) > 0)
            OR (key_kind <> 'rsa' AND rsa_exponent IS NULL)
        ),
    -- An uncompressed P-256 point is 65 bytes and a P-384 point is 97. Pinned exactly, because a
    -- point of the wrong length for its curve is a configuration error and `ring` would answer
    -- the same "signature did not verify" for it as for a forgery.
    CONSTRAINT saml_connection_certificates_point_length
        CHECK (
            (key_kind = 'ecdsa_p256' AND octet_length(public_key) = 65)
            OR (key_kind = 'ecdsa_p384' AND octet_length(public_key) = 97)
            -- RSA IN THE RANGE `ring` VERIFIES, which is 2048 to 8192 bits: the algorithms this
            -- system uses are `RSA_PKCS1_2048_8192_SHA{256,384,512}` (ironauth-jose's
            -- `xmldsig.rs`), so the modulus is 256 to 1024 bytes.
            --
            -- THE FLOOR IS THE POINT, and the first version had it at 128 bytes -- 1024 bits,
            -- which `ring` refuses. A key stored there is one the verifier will not accept, and
            -- the refusal arrives at somebody's sign-in as "the signature did not verify", which
            -- is the answer a forgery gets.
            --
            -- A RANGE AND NOT AN ENUMERATION. A version of this named 256, 384 and 512 as "the
            -- three sizes ring will verify", which is false: 5120, 6144 and 8192-bit keys verify
            -- too, and an identity provider using one would have been unable to configure a
            -- connection at all. A bound that refuses valid input is worse than a loose one,
            -- because the loose one fails visibly at the first signature.
            OR (key_kind = 'rsa' AND octet_length(public_key) BETWEEN 256 AND 1024)
        ),
    CONSTRAINT saml_connection_certificates_fingerprint_length
        CHECK (octet_length(fingerprint_sha256) = 32),
    CONSTRAINT saml_connection_certificates_der_bounded
        CHECK (octet_length(certificate_der) BETWEEN 1 AND 16384),
    -- VALIDITY MUST BE AN INTERVAL. A certificate whose `not_after` precedes its `not_before` is
    -- one no clock can be inside, so pinning it would be pinning nothing.
    CONSTRAINT saml_connection_certificates_validity_ordered
        CHECK (not_before < not_after),

    -- THE SAME KEY CANNOT BE PINNED TWICE ON ONE CONNECTION. Two rows with one key would make
    -- "remove the old certificate" ambiguous, and during a rollover that is exactly the operation
    -- an operator is performing under time pressure.
    CONSTRAINT saml_connection_certificates_one_per_key
        UNIQUE (tenant_id, environment_id, connection_id, fingerprint_sha256),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- CASCADE, unlike the organization keys elsewhere. A pin has no meaning without its
    -- connection: leaving orphans behind would leave trust anchors in the table for a connection
    -- an operator believes they deleted.
    FOREIGN KEY (connection_id) REFERENCES saml_connections (id) ON DELETE CASCADE
);

-- The ACS reads every live pin for one connection, and reads it on every sign-in.
CREATE INDEX saml_connection_certificates_by_connection
    ON saml_connection_certificates (tenant_id, environment_id, connection_id);

-- NO INDEX ON `not_after`. One was here, justified by "the listing route in this slice orders by
-- it", and that was false: the only read orders by `created_at`. #141's expiry sweep is the query
-- that wants it, and the index belongs in the migration that adds the sweep -- which is the rule
-- 0189 states about a grant and which applies to an index for the same reason.

ALTER TABLE saml_connection_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_connection_certificates FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_connection_certificates_scope ON saml_connection_certificates
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Pinning and unpinning are operator actions on the control plane, like the connection itself.
GRANT SELECT, INSERT, DELETE ON saml_connection_certificates TO ironauth_control;

-- The data plane READS, because the ACS verifies there. It never writes a trust anchor.
GRANT SELECT ON saml_connection_certificates TO ironauth_app;
