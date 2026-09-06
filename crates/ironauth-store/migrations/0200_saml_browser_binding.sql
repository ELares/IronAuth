-- The browser binding for a SAML outstanding request (issue #139).
--
-- WHAT IT CLOSES. The outstanding-request row proves a response answers a request THIS
-- deployment issued and has not spent. It does not prove the browser presenting the response is
-- the browser the request was issued to, and the start endpoint is unauthenticated -- so anybody
-- can start a flow, authenticate at the identity provider as THEMSELVES, capture the resulting
-- SAMLResponse, and auto-submit it into somebody else's browser. Before sign-in that bought an
-- attacker nothing, because the assertion consumer minted no session. It now does, and a forced
-- sign-in puts a victim in the attacker's account: everything the victim then does -- uploads a
-- document, connects an integration, changes a password -- happens inside an account the
-- attacker controls and can read at leisure. This is login CSRF, and the assertion-id replay
-- cache does not touch it: the assertion is fresh, genuine, and used exactly once.
--
-- A DIGEST, NOT THE VALUE. The column holds SHA-256 of a random nonce the start endpoint puts in
-- a cookie, so a reader of this table cannot mint the cookie that satisfies it. The nonce is the
-- secret; this is the verifier.
--
-- NULLABLE, AND THAT IS NOT A LOOPHOLE. Two shapes have no binding and must not be locked out:
-- a request issued by a build before this column existed, which drains within its own five
-- minute TTL, and an UNSOLICITED response, which by definition answers no request and therefore
-- has no row here at all. Unsolicited responses are refused by default; a connection whose
-- operator opts in accepts that this defence does not apply to it, which is what #139 means by
-- "documented risk in the connection config". The consumer treats NULL as "nothing to check"
-- rather than "check passed", and those are the same only because a NULL can only arise from
-- those two cases -- the issuer always writes one.
ALTER TABLE saml_outstanding_requests
    ADD COLUMN browser_binding_sha256 bytea;

-- EXACTLY 32 BYTES WHEN PRESENT. A shorter value is not a SHA-256 digest, and accepting one
-- would let a caller store a truncated comparison that is cheaper to collide.
ALTER TABLE saml_outstanding_requests
    ADD CONSTRAINT saml_outstanding_requests_binding_is_sha256
    CHECK (browser_binding_sha256 IS NULL OR octet_length(browser_binding_sha256) = 32);

COMMENT ON COLUMN saml_outstanding_requests.browser_binding_sha256 IS
    'SHA-256 of the nonce in the browser-binding cookie the start endpoint set; NULL for an '
    'unsolicited response or a request issued before this column existed (issue #139).';
