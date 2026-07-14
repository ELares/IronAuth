-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Dynamic Client Registration and client-configuration management (issue #30).
--
-- RFC 7591 (dynamic client registration) creates a client from a metadata
-- document, and RFC 7592 (client configuration management) reads, updates, and
-- deletes it later through a per-client registration access token. Both are the
-- SAME clients table the rest of the provider already registers into, so this is
-- a pure additive (expand) ALTER of clients: five nullable/defaulted columns,
-- safe for the old binary to ignore. No new table is introduced, so this
-- migration adds NO new row-level-security obligation. The clients table already
-- ENABLEs + FORCEs row-level security and carries the (tenant, environment)
-- isolation policy and the nonempty-scope CHECK from 0001, all of which apply to
-- these columns unchanged.
--
-- The key/algorithm registration a DCR client needs for private_key_jwt (`jwks`,
-- `jwks_uri`, `token_endpoint_auth_signing_alg`), its secret hash, and its
-- redirect URI set already exist on clients from 0006/0008/0013, so DCR reuses
-- them. The columns below are the DCR-specific additions.

-- The SHA-256 (hex) of the RFC 7592 registration access token. Like every other
-- credential in this provider (client secrets, management keys) the token itself
-- NEVER touches the database: the plaintext is returned once at registration (and
-- again, freshly rotated, on every successful update) and only its hash is
-- stored, so a database dump contains nothing replayable. NULL for a client that
-- did not originate through dynamic registration.
ALTER TABLE clients ADD COLUMN registration_access_token_hash text;

-- The RFC 7592 client configuration endpoint URL for this client
-- ({issuer}/connect/register/{client_id}). Stored so read/update/delete echo the
-- exact value a client was handed at registration. NULL for a non-DCR client.
ALTER TABLE clients ADD COLUMN registration_client_uri text;

-- The negotiated id_token_signed_response_alg (OpenID Connect RP Metadata Choices
-- 1.0): the JWS algorithm this client asked its ID tokens be signed with, chosen
-- by the OP from the client's acceptable set (EdDSA preferred, else RS256). The
-- spec default is RS256 when the client expresses no preference. NULL for a client
-- registered before DCR (which carries no per-client id_token signing preference).
ALTER TABLE clients ADD COLUMN id_token_signed_response_alg text;

-- The RFC 8252 / OIDC DCR application_type: 'web' or 'native'. It governs which
-- redirect URI shapes the client may register (web: https only; native: https,
-- http loopback IP literals, and reverse-domain private-use schemes). NULL for a
-- non-DCR client.
ALTER TABLE clients ADD COLUMN application_type text;

-- Whether this client originated through dynamic client registration (RFC 7591).
-- Only a DCR-origin client is manageable through the RFC 7592 configuration
-- endpoint, so read/update/delete there filter on this flag. Additive with a
-- default of false, so every pre-existing client is (correctly) not a DCR client.
ALTER TABLE clients ADD COLUMN dcr_registered boolean NOT NULL DEFAULT false;
