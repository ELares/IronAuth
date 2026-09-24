-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The mTLS client-authentication metadata (issue #159).
--
-- RFC 8705's two methods:
--
--   self_signed_tls_client_auth: the client registers THE certificate every request
--     must present (exact DER equality + validity at the request instant). The
--     registered value is the certificate PEM. No CA is involved, so no trust-anchor
--     configuration stands between the method and its first caller.
--
--   tls_client_auth (the PKI method): the client registers the expected subject
--     (RFC 8705 section 2.1.2: the exact subject distinguished name, or a SAN-based
--     alternative), and the server validates the presented certificate's chain
--     against the configured trust anchors. The subject column is additive here; the
--     chain-validation surface lands with the method's configuration.
--
-- The constraint mirrors 0013's private_key_jwt discipline: a client registered for
-- self_signed_tls_client_auth MUST have registered a certificate, so a method
-- registered without its credential fails LOUD at registration, not per request.
-- The PKI method's subject is OPTIONAL in this migration: the SAN-based alternatives
-- of RFC 8705 section 2.1.2 will add their own columns, and the chain-validation
-- surface is where the requirement becomes mandatory.
--
-- EXPAND: additive columns and a CHECK scoped to one method; existing rows are
-- unaffected (the columns default to NULL).
ALTER TABLE clients
    ADD COLUMN tls_client_auth_cert text,
    ADD COLUMN tls_client_auth_subject_dn text;

ALTER TABLE clients ADD CONSTRAINT clients_self_signed_tls_auth_has_cert
    CHECK (
        token_endpoint_auth_method <> 'self_signed_tls_client_auth'
        OR tls_client_auth_cert IS NOT NULL
    );