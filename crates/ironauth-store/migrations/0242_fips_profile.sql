-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The per-environment FIPS tenant profile flag (issue #162).
--
-- A FIPS-profile environment signs with the validated-module-compatible set:
-- ES256 (the default), RS256 (available), and EdDSA UNAVAILABLE -- the
-- per-tenant algorithm policy the FIPS posture page recommends, applied as a
-- configuration stance rather than a code fork. The nuance it exists for:
-- even with a validated module server-side, client-side validated coverage for
-- EdDSA verification is thin and CNSA 2.0 excludes EdDSA entirely, so
-- FIPS-constrained environments default to ES256 today.
--
-- The environment_guardrails VIEW (migrations 0029, 0237) is recreated with
-- the new column: the data plane reads the flag through the same scope-forced
-- projection it reads the other guardrails through.
--
-- EXPAND: additive column + a view recreation; existing rows default to false
-- (not a FIPS profile).
ALTER TABLE environments ADD COLUMN fips_profile boolean NOT NULL DEFAULT false;

CREATE OR REPLACE VIEW environment_guardrails AS
    SELECT tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, fips_profile
    FROM environments
    WHERE tenant_id = current_setting('ironauth.tenant_id', true)
      AND id = current_setting('ironauth.environment_id', true);