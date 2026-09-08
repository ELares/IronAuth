-- The `audit` portal intent (issue #141 criterion 4).
--
-- #141 asks for "a per-org audit viewer in the portal: customer admins search their own org's
-- events". That surface needs an intent for the reason every portal surface does: the fence in
-- `portal_route` refuses a session reaching a surface its link was not minted for, and it can
-- only fence a value that exists.
--
-- WHY NOT REUSE `contacts` OR `sso`. Reading a history and changing a configuration are
-- different authorities, and this is the one an operator is most likely to want to hand out
-- narrowly: an auditor or a compliance reviewer should be able to read what happened without
-- also being able to alter anything. A link that carried both would make that impossible to
-- express.
--
-- BOTH TABLES. 0203 pins the closed set on `portal_links`, 0204 pins the same set on
-- `portal_sessions`, and widening one alone mints links that can never be redeemed -- the mint
-- succeeds, the session insert fails, and the holder is told "temporarily unavailable" for ever.
-- 0209 did that before its tests caught it.

ALTER TABLE portal_links
    DROP CONSTRAINT portal_links_intent_known;

ALTER TABLE portal_links
    ADD CONSTRAINT portal_links_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal', 'contacts', 'audit'));

ALTER TABLE portal_sessions
    DROP CONSTRAINT portal_sessions_intent_known;

ALTER TABLE portal_sessions
    ADD CONSTRAINT portal_sessions_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal', 'contacts', 'audit'));

-- NO NEW GRANT. 0002 already gives `ironauth_app` SELECT on `audit_log`, and this surface only
-- reads. What confines it to one organization is not a grant but the query:
-- `AuditRepo::search_for_organization` takes the organization as a required argument and matches
-- `organization_id = $3`, which also excludes every NULL row -- and 0138 records that most audit
-- rows are NULL, being the vendor's own tenant-level operations rather than any customer's.
