-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- What a stored connection needs in order to REFRESH itself (issue #132, criterion 3).
--
-- Criterion 3 is "stored-token refresh works and a failing connection isolates without
-- affecting other connections". The isolation half shipped with 0178: a broken connection is
-- MARKED rather than deleted, so one dead downstream is visible and does not take an agent's
-- other connections with it. The refresh half did not, and could not: refreshing an OAuth
-- credential means presenting the stored refresh token at the PROVIDER's token endpoint with
-- the client credentials that provider issued, and none of those three things had anywhere to
-- live. The vault stored a refresh token nothing could spend.
--
-- ON THE CONNECTION, not in a per-provider config table. The tempting shape is one row per
-- provider per environment, and it is wrong here for a reason worth writing down: two agents
-- in the same environment can legitimately hold connections issued to DIFFERENT downstream
-- OAuth clients, because the downstream client is chosen by whoever ran the consent flow, not
-- by IronAuth. A per-provider table would force them to share one, and the first agent whose
-- credential was minted by a different client would silently fail to refresh.
--
-- ALL THREE NULLABLE, and null means "this connection cannot refresh". That is a fact about
-- the connection rather than missing data: a credential established through a flow that
-- returned no refresh token, or one an operator stored by hand, simply has to be re-established
-- when it expires. The exchange says so distinctly rather than reporting it as a failure.
--
-- The client SECRET is sealed exactly as the two token columns are, under its own purpose tag,
-- so it cannot be opened as an access token or a refresh token and neither can be opened as it.
-- It is the third secret in this table and it gets the same treatment as the first two: there
-- is no window in which it sits readable.

ALTER TABLE agent_vault_connections
    ADD COLUMN refresh_token_endpoint text,
    ADD COLUMN refresh_client_id text,
    ADD COLUMN refresh_client_secret_sealed bytea,
    ADD COLUMN refresh_client_secret_dek_version integer;

-- The four travel together or not at all. A partially configured refresh is a refresh that
-- fails at the provider rather than at the edge, which turns an operator's incomplete input
-- into a downstream error nobody can act on.
ALTER TABLE agent_vault_connections
    ADD CONSTRAINT agent_vault_connections_refresh_config_paired
    CHECK (
        (refresh_token_endpoint IS NULL
         AND refresh_client_id IS NULL
         AND refresh_client_secret_sealed IS NULL
         AND refresh_client_secret_dek_version IS NULL)
        OR
        (refresh_token_endpoint IS NOT NULL
         AND refresh_client_id IS NOT NULL
         AND refresh_client_secret_sealed IS NOT NULL
         AND refresh_client_secret_dek_version IS NOT NULL)
    );

-- https only, checked here rather than only at the edge. This URL is dereferenced by the
-- server with a refresh token in the body: a plaintext one puts the credential on the wire.
-- The bound is generous against any real endpoint and small against a hostile one.
ALTER TABLE agent_vault_connections
    ADD CONSTRAINT agent_vault_connections_refresh_endpoint_https
    CHECK (
        refresh_token_endpoint IS NULL
        OR (refresh_token_endpoint LIKE 'https://%' AND char_length(refresh_token_endpoint) <= 2048)
    );

COMMENT ON COLUMN agent_vault_connections.refresh_token_endpoint IS
    'Issue #132: the provider token endpoint the stored refresh token is spent at. NULL means '
    'this connection cannot refresh and must be re-established when it expires.';
COMMENT ON COLUMN agent_vault_connections.refresh_client_secret_sealed IS
    'Issue #132: the downstream client secret, sealed under its own purpose tag so it cannot '
    'be opened as an access or refresh token, and neither can be opened as it.';
