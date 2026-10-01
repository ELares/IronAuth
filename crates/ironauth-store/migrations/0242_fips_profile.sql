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

DO $fips_view$
DECLARE
    names text[];
    projection text;
BEGIN
    SELECT array_agg(attname::text ORDER BY attnum) INTO names
      FROM pg_attribute WHERE attrelid = 'environment_guardrails'::regclass
        AND attnum > 0 AND NOT attisdropped;
    IF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened';
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','auto_link_posture','fapi_hardened'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, auto_link_posture, fapi_hardened';
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened','auto_link_posture'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, auto_link_posture';
    ELSE
        RAISE EXCEPTION 'unexpected environment_guardrails shape; manual migration review required';
    END IF;
    EXECUTE 'CREATE TEMP VIEW ironauth_expected_guardrails AS SELECT ' || projection ||
        ' FROM environments WHERE tenant_id = current_setting(''ironauth.tenant_id'', true)' ||
        ' AND id = current_setting(''ironauth.environment_id'', true)';
    IF pg_get_viewdef('environment_guardrails'::regclass) <>
       pg_get_viewdef('pg_temp.ironauth_expected_guardrails'::regclass) THEN
        RAISE EXCEPTION 'unexpected environment_guardrails definition; manual migration review required';
    END IF;
    DROP VIEW pg_temp.ironauth_expected_guardrails;
    IF NOT 'fips_profile' = ANY(names) THEN
        EXECUTE 'CREATE OR REPLACE VIEW environment_guardrails AS SELECT ' || projection ||
            ', fips_profile FROM environments WHERE tenant_id = current_setting(''ironauth.tenant_id'', true)' ||
            ' AND id = current_setting(''ironauth.environment_id'', true)';
    END IF;
END
$fips_view$;
