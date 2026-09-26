-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The per-environment FAPI 2.0 hardened-mode flag (issue #156).
--
-- A hardened environment enforces the FAPI 2.0 Security Profile (Final)
-- end to end: PAR mandatory, PKCE S256 only, client authentication restricted
-- to private_key_jwt / mTLS (no public clients), sender-constrained tokens
-- only, the PS256/ES256/EdDSA signing set, and non-disableable RFC 9207 iss.
-- The enforcement lives in the request paths (crates/ironauth-oidc); this
-- column is the environment's switch.
--
-- The environment_guardrails VIEW (migration 0029) is recreated with the new
-- column: the data plane reads the flag through the same scope-forced
-- projection it reads the guardrail kind through, so it never needs a direct
-- grant on the environments level table.
--
-- EXPAND: additive column + a view recreation; existing rows default to false
-- (not hardened).
ALTER TABLE environments ADD COLUMN fapi_hardened boolean NOT NULL DEFAULT false;

CREATE OR REPLACE VIEW environment_guardrails AS
    SELECT tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened
    FROM environments
    WHERE tenant_id = current_setting('ironauth.tenant_id', true)
      AND id = current_setting('ironauth.environment_id', true);