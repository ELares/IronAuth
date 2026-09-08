-- The `certificate-renewal` portal intent (issue #141 criterion 2).
--
-- 0203 shipped `portal_links.intent` as a CLOSED set and said why: "a new portal surface cannot
-- be reached until somebody has written down that it exists". Widening it is therefore a
-- migration on purpose, and this is that writing-down.
--
-- WHY A SEPARATE INTENT rather than reusing `sso`. An `sso` link is the operator's whole SSO
-- configuration surface: the connection, its endpoints, its attribute mapping. A renewal link is
-- handed to somebody with one job -- replace the signing certificate before it expires -- and
-- that person is frequently NOT the person who set SSO up. #141 says the alert has to land
-- somewhere real, and a link that lands on a full configuration page gives its holder every
-- other setting on that connection as well. The intent fence in `portal_route` is what makes the
-- narrower link narrower, and the fence only has something to enforce if the intent is its own
-- value.
--
-- NO COLUMN CHANGES. The renewal surface reads the connection and its pinned certificates
-- through the tables that already hold them; a link carries an organization and an intent, which
-- is all `portal_links` has ever carried.

ALTER TABLE portal_links
    DROP CONSTRAINT portal_links_intent_known;

-- The same closed set, plus one. Re-added rather than left off: a table whose intent column
-- accepts anything is one typo away from a link nothing will ever serve, and the redeem would
-- mint a session for a surface that does not exist.
ALTER TABLE portal_links
    ADD CONSTRAINT portal_links_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal'));

-- AND THE SESSION TABLE, which carries its own copy of the same closed set. 0204 states the
-- invariant it keeps: "a session cannot carry an intent no link could have been minted with,
-- which keeps 'the session's intent came from a link' true in the schema". Widening only
-- `portal_links` therefore mints a link that can never be redeemed -- the mint succeeds, the
-- POST that opens a session fails on THIS check, and the holder is told "temporarily
-- unavailable" about a link that will never work. That is exactly what this migration did when
-- it touched one table, and the portal tests are what said so.
ALTER TABLE portal_sessions
    DROP CONSTRAINT portal_sessions_intent_known;

ALTER TABLE portal_sessions
    ADD CONSTRAINT portal_sessions_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams',
                          'certificate-renewal'));

-- NOT VALIDATED SEPARATELY, and worth saying why the plain ADD is right here. `ADD CONSTRAINT
-- ... CHECK` takes ACCESS EXCLUSIVE and scans the table, which on a big table is the kind of
-- lock that stalls a deployment. Both tables here hold only live rows -- a five-minute link TTL
-- by default, a short session, both swept -- so each scan is over a table that is small by
-- construction rather than by luck. A NOT VALID / VALIDATE split would buy nothing and would leave a window
-- in which the column accepts values the code cannot serve.
