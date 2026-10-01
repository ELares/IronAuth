-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Repair the exact historical view without changing existing column positions,
-- ownership, grants or dependent views. Retain the published FIPS projection.
DO $repair$
DECLARE
    names text[];
    projection text;
BEGIN
    SELECT array_agg(attname::text ORDER BY attnum) INTO names
      FROM pg_attribute WHERE attrelid = 'environment_guardrails'::regclass
        AND attnum > 0 AND NOT attisdropped;
    IF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened','fips_profile'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, fips_profile';
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','auto_link_posture','fapi_hardened','fips_profile'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, auto_link_posture, fapi_hardened, fips_profile';
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened','auto_link_posture','fips_profile'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, auto_link_posture, fips_profile';
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened','fips_profile','auto_link_posture'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, fips_profile, auto_link_posture';
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
    IF NOT 'auto_link_posture' = ANY(names) THEN
        EXECUTE 'CREATE OR REPLACE VIEW environment_guardrails AS SELECT ' || projection ||
            ', auto_link_posture FROM environments WHERE tenant_id = current_setting(''ironauth.tenant_id'', true)' ||
            ' AND id = current_setting(''ironauth.environment_id'', true)';
    END IF;
END
$repair$;
