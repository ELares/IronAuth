-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Forward repair for the exact historical 0237 view-definition error.
-- CREATE OR REPLACE preserves ownership, grants and existing column positions;
-- no DROP/CASCADE or table data changes. Corrected fresh chains are a no-op.
DO $repair$
DECLARE
    names text[];
    projection text;
    old_shape boolean;
BEGIN
    SELECT array_agg(a.attname::text ORDER BY a.attnum) INTO names
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      WHERE c.oid = 'environment_guardrails'::regclass AND c.relkind = 'v'
        AND a.attnum > 0 AND NOT a.attisdropped;
    IF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened';
        old_shape := true;
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','auto_link_posture','fapi_hardened'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, auto_link_posture, fapi_hardened';
        old_shape := false;
    ELSIF names = ARRAY['tenant_id','environment_id','kind','custom_domain','fapi_hardened','auto_link_posture'] THEN
        projection := 'tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, auto_link_posture';
        old_shape := false;
    ELSE
        RAISE EXCEPTION 'unexpected environment_guardrails shape; manual migration review required';
    END IF;
    -- Compare parsed/deparsed definitions, not whitespace in hand-written SQL.
    -- An unexpected filter, relation, expression or function dependency is refused
    -- instead of replacing a customized security boundary without review.
    EXECUTE 'CREATE TEMP VIEW ironauth_0237_expected_guardrails AS SELECT ' || projection ||
        ' FROM environments WHERE tenant_id = current_setting(''ironauth.tenant_id'', true)' ||
        ' AND id = current_setting(''ironauth.environment_id'', true)';
    IF pg_get_viewdef('environment_guardrails'::regclass) <>
       pg_get_viewdef('pg_temp.ironauth_0237_expected_guardrails'::regclass) THEN
        RAISE EXCEPTION 'unexpected environment_guardrails definition; manual migration review required';
    END IF;
    DROP VIEW pg_temp.ironauth_0237_expected_guardrails;
    IF old_shape THEN
        CREATE OR REPLACE VIEW environment_guardrails AS
            SELECT tenant_id, id AS environment_id, kind, custom_domain,
                   fapi_hardened, auto_link_posture
            FROM environments
            WHERE tenant_id = current_setting('ironauth.tenant_id', true)
              AND id = current_setting('ironauth.environment_id', true);
    END IF;
END
$repair$;
