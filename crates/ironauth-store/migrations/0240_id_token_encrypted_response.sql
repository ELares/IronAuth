-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The encrypted ID-token response algorithms (issue #158).
--
-- A client that registers `id_token_encrypted_response_alg` (with the optional
-- `id_token_encrypted_response_enc`) receives its ID tokens as sign-then-encrypt
-- nested JWTs: the JWS is the plaintext of a JWE to the client's registered
-- public key. `NULL` (the default) keeps the plain signed ID token.
--
-- EXPAND: additive columns; existing rows default to NULL.
ALTER TABLE clients ADD COLUMN id_token_encrypted_response_alg text;
ALTER TABLE clients ADD COLUMN id_token_encrypted_response_enc text;