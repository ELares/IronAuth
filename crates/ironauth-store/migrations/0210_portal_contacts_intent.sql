-- The `contacts` portal intent (issue #141 criterion 3).
--
-- #141 asks that IT contacts be "manageable in the portal (by the org's IT admin) and via the
-- management API". The management half shipped with 0207; this is the portal's half, and it
-- needs an intent for the same reason `certificate-renewal` did: the fence in `portal_route`
-- refuses a session reaching a surface its link was not minted for, and it can only fence a
-- value that exists.
--
-- WHY NOT REUSE `sso`. The person who maintains a customer's notification list is an
-- administrator, not necessarily the person who configured single sign-on, and a link that
-- opened the whole SSO surface to change an email address would hand its holder every setting on
-- the connection. The narrow link is the point of the intent set being closed.
--
-- BOTH TABLES, and this is the half a previous widening missed. 0203 pins the closed set on
-- `portal_links` and 0204 pins the SAME set on `portal_sessions`, which is what keeps "a
-- session's intent came from a link" true in the schema rather than only in the handler. Widening
-- one of them mints links that can never be redeemed: the mint succeeds, the POST that opens a
-- session fails, and the holder is told "temporarily unavailable" about a link that will never
-- work. 0209 did exactly that before its tests caught it.

ALTER TABLE portal_links
    DROP CONSTRAINT portal_links_intent_known;

ALTER TABLE portal_links
    ADD CONSTRAINT portal_links_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal', 'contacts'));

ALTER TABLE portal_sessions
    DROP CONSTRAINT portal_sessions_intent_known;

ALTER TABLE portal_sessions
    ADD CONSTRAINT portal_sessions_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal', 'contacts'));

-- NO NEW GRANT, and that is deliberate. 0207 gives `ironauth_app` SELECT on `org_contacts` and
-- nothing else; the portal serves on that role, so this intent buys a READ surface. Managing a
-- contact from the portal is a control-plane write and rides a queue, the way a pasted
-- certificate does -- see `CERTIFICATE_PIN_REQUEST_CONSUMER` for the shape and the reasoning.
