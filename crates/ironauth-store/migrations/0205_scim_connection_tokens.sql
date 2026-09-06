-- A SCIM connection's bearer tokens, so one connection can hold two at once (issue #140).
--
-- # Why the token has to leave the connection row
--
-- `scim_connections.token_digest` is that table's PRIMARY KEY, so a connection IS a token:
-- rotating one is creating a different connection with a different id. `ScimEnterpriseRepo`'s
-- own doc records what that costs and says it was MEASURED -- "a rotation is a new row with a
-- new id and every attribute the old connection wrote would be stranded" -- which is why the
-- enterprise attributes are keyed on the organization rather than the connection.
--
-- #140 asks for something that shape cannot express: "SCIM token rotation provides an overlap
-- window during which both tokens authenticate, then the old token fails closed". Two live
-- tokens for one connection is two rows here, and the connection keeps its id, its provider,
-- its display name and everything downstream keyed on it.
--
-- WHY AN OVERLAP AT ALL. The token lives in an identity provider's configuration, which a
-- customer's IT admin edits by hand. Between minting the new one and pasting it into Okta there
-- is a window, and if the old token dies at the moment the new one is minted, provisioning is
-- down for exactly as long as that window lasts -- on a schedule nobody controls, for a system
-- whose failure looks like employees not being deprovisioned. WorkOS productised this in June
-- 2026 for the same reason. The overlap makes the cutover the admin's business rather than a
-- race.
--
-- # Expand phase, and what an old binary does, stated correctly
--
-- `scim_connections.token_digest` STAYS, carrying whatever value it had, and every existing
-- digest is backfilled here. An old binary keeps authenticating against that COLUMN and knows
-- nothing about this table.
--
-- AN EARLIER VERSION OF THIS COMMENT CLAIMED THAT WAS THE SAFE DIRECTION -- "a rolling upgrade
-- degrades to the new token does not work yet, never to a superseded token still does". IT IS
-- EXACTLY BACKWARDS, and the correction matters more than the original claim did.
--
-- A rotation writes the superseded token's horizon into THIS table. It cannot write it onto
-- `scim_connections`, whose `expires_at` bounds the CONNECTION rather than any one token, and
-- setting that would kill the freshly minted token too. So an un-upgraded replica goes on
-- reading the original digest out of a column no rotation touches, and keeps honouring the
-- superseded token for as long as it stays un-upgraded. That is precisely "a superseded token
-- still does".
--
-- WHAT FOLLOWS FROM THAT, operationally: FINISH THE ROLLOUT BEFORE ROTATING. Until every replica
-- serving SCIM has this migration and the binary that reads this table, a rotation is not a
-- revocation, and a rotation performed to contain a LEAKED token is not containment.
--
-- IT IS NOT FIXABLE WITHOUT REOPENING A WORSE HOLE. Making the rotation blank or swap
-- `scim_connections.token_digest` would need `GRANT UPDATE (token_digest)`, and 0183's own
-- comment records why that grant does not exist: a whole-table UPDATE let the control role
-- "swap `token_digest` for one it chose", which is a way to install a known credential. Trading
-- a bounded rollout window for a standing privilege escalation is the wrong trade, so the window
-- is documented instead of coded away.
--
-- The column's removal is a contract-phase change for a later release, once no binary reads it.
-- After that removal the window closes on its own.
CREATE TABLE scim_connection_tokens (
    -- The SHA-256 hex digest of the whole presented bearer token, and the verification lookup
    -- key, exactly as it was on `scim_connections`.
    token_digest      text        PRIMARY KEY,
    -- The connection this token authenticates as. Several rows may name one connection: that is
    -- the entire point of the table.
    connection_id     text        NOT NULL,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- WHEN THIS TOKEN STOPS WORKING. NULL means no horizon of its own; a rotation sets it on
    -- the SUPERSEDED token to the end of the overlap window, which is what makes the old one
    -- fail closed rather than linger.
    expires_at        timestamptz,
    -- Revoked outright, skipping any remaining overlap. For a leak, where the window is the
    -- problem rather than the point.
    revoked_at        timestamptz,

    CONSTRAINT scim_connection_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- 64 lowercase hex characters, as on `scim_connections`: a shorter value is a truncated
    -- digest, and a truncated digest compares equal more often than it should.
    CONSTRAINT scim_connection_tokens_digest_shaped
        CHECK (token_digest ~ '^[0-9a-f]{64}$'),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The connection must EXIST. Referential integrity bypasses row-level security, so an
    -- id-only key admits any globally existing connection; what refuses a cross-scope one is
    -- the repository, which takes a scope-checked `ScimConnectionId`. 0183 records the same
    -- reasoning for its own organization key, and `scim_connections.id` is UNIQUE there, which
    -- is what lets this reference exist at all.
    FOREIGN KEY (connection_id) REFERENCES scim_connections (id)
);

-- The rotation reads a connection's tokens to supersede them; the listing shows an operator
-- which tokens are live and when each lapses.
CREATE INDEX scim_connection_tokens_by_connection
    ON scim_connection_tokens (tenant_id, environment_id, connection_id, created_at);

-- EVERY EXISTING TOKEN, COPIED, so authentication through this table answers for connections
-- created before it existed. Without the backfill the new read path would refuse every token in
-- a deployed database, which is an outage rather than a migration.
--
-- The connection's own `expires_at` and `revoked_at` come across too: they were the token's
-- horizons when the token and the connection were one row, and they still are.
INSERT INTO scim_connection_tokens
    (token_digest, connection_id, tenant_id, environment_id, created_at, expires_at, revoked_at)
SELECT token_digest, id, tenant_id, environment_id, created_at, expires_at, revoked_at
FROM scim_connections;

ALTER TABLE scim_connection_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_connection_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_connection_tokens_scope ON scim_connection_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE CONTROL PLANE MINTS AND SUPERSEDES, mirroring 0183: creating a provisioning credential is
-- an operator action, and so is rotating one.
--
-- UPDATE IS COLUMN SCOPED, for the reason 0183 gives and 0123 gave before it. A table-wide
-- UPDATE would let the control role re-point `connection_id` at another connection or swap
-- `token_digest` for one it chose -- so the boundary this table exists to enforce, and the
-- verifier itself, would be editable by the role that mints tokens. A rotation writes exactly
-- two columns: the horizon of the token being superseded, and, for a leak, its revocation.
GRANT SELECT, INSERT ON scim_connection_tokens TO ironauth_control;
GRANT UPDATE (expires_at, revoked_at) ON scim_connection_tokens TO ironauth_control;

-- REVOCATION IS ONE WAY, as it is on the connection. The column grant above cannot express it,
-- because `revoked_at` is exactly the column a revoke must write.
--
-- AS RESTRICTIVE, deliberately: `scim_connection_tokens_scope` has no FOR or TO clause, so a
-- permissive narrowing would be OR'd with a check the offending update already satisfies and
-- would constrain nothing. 0181, 0182 and 0183 record the same reasoning.
--
-- WHICH CLAUSE DOES WHAT, stated correctly because the first version of this comment got it
-- backwards. It is the USING clause that forbids un-revocation: it admits only rows where
-- `revoked_at IS NULL`, so an already-revoked row is not visible to an UPDATE at all and cannot
-- be cleared. The WITH CHECK does NOT enforce that -- `SET revoked_at = NULL, expires_at = ...`
-- satisfies it, because `expires_at IS NOT NULL` makes the OR true.
--
-- WHAT THE WITH CHECK IS FOR is narrower: it refuses an UPDATE that leaves a row with neither a
-- revocation nor a horizon, which is a "supersede" that superseded nothing. Every legitimate
-- write here sets one or the other.
--
-- The distinction matters for the next person: somebody who believed the WITH CHECK carried the
-- one-way property could relax USING to `true` -- to touch an already-revoked row -- and would
-- reopen un-revocation while the clause they trusted still passed.
CREATE POLICY scim_connection_tokens_revoke_is_one_way
    ON scim_connection_tokens
    AS RESTRICTIVE
    FOR UPDATE
    TO ironauth_control
    USING (revoked_at IS NULL)
    WITH CHECK (revoked_at IS NOT NULL OR expires_at IS NOT NULL);

-- The DATA plane READS, because every SCIM request authenticates against this table. It may not
-- write: a provisioning credential that could mint another would be a privilege escalation with
-- no operator in the loop.
GRANT SELECT ON scim_connection_tokens TO ironauth_app;

COMMENT ON TABLE scim_connection_tokens IS
    'Issue #140: the bearer tokens of one inbound SCIM connection. Several may be live at once, '
    'which is what makes a rotation an overlap rather than a cutover: the superseded token gets '
    'an expiry at the end of the window and fails closed after it.';
