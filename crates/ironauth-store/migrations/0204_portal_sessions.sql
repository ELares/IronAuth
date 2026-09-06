-- The self-service portal's SESSION, minted by redeeming an entry link (issue #140).
--
-- WHY IT IS A SECOND TABLE AND NOT A COLUMN ON `portal_links`. The link and the session answer
-- different questions over different spans. The link asks "may this person START", and #140
-- wants that window measured in minutes because the link is handed over out of band -- pasted
-- into a ticket, an email, a chat -- and every one of those keeps a copy. The session asks "may
-- this request CONTINUE", and an IT admin configuring SSO against an identity provider they
-- also have to log into needs considerably longer than five minutes. One row cannot carry both
-- horizons, and collapsing them would force a choice between a link that stays redeemable for
-- an hour and a session that dies mid-setup.
--
-- A DIGEST, NEVER THE COOKIE. Same posture as `portal_links` and `magic_link_tokens` before it:
-- the row holds SHA-256 of a CSPRNG value that exists only in the browser's cookie jar, so
-- whoever can read this table cannot then walk into a customer's organization.
--
-- THE ORGANIZATION AND THE INTENT ARE COPIED, NOT JOINED. They are the session's whole
-- authority, and #140 requires that "a portal session for org A cannot read or mutate any org B
-- state" and that "an sso link cannot reach SCIM or domain-verification surfaces". Copying them
-- at redemption makes the session's reach a fact fixed at mint time: deleting the link, or a
-- later change to it, cannot widen a session that is already open. A join would leave the
-- session's authority answerable by a row somebody else can still write.
CREATE TABLE portal_sessions (
    -- The pss_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The link this was redeemed from, for the audit trail. NOT the source of the session's
    -- authority: that is the two columns below.
    portal_link_id    text        NOT NULL,
    -- The ONE organization this session may see.
    organization_id   text        NOT NULL,
    -- The ONE surface it may reach.
    intent            text        NOT NULL,
    -- SHA-256 of the cookie value. Never the value itself.
    token_digest      bytea       NOT NULL,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    -- Set when an admin finishes, by the portal's own finish route. A revoked session is kept
    -- rather than deleted so the audit trail still resolves the id its rows are attributed to.
    --
    -- THERE IS NO OPERATOR-FACING REVOCATION YET: the management API cannot end somebody else's
    -- portal session, and the grants at the foot of this file match that rather than
    -- anticipating it. Killing the organization does end every session over it --
    -- `authenticate` joins `organizations` and requires it live and active on every request --
    -- but that is a blunter instrument than an operator ending one session, and the narrower
    -- control lands with the operational surfaces in a later slice of #140.
    revoked_at        timestamptz,

    CONSTRAINT portal_sessions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT portal_sessions_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    -- THE SAME CLOSED SET `portal_links` PINS. A session cannot carry an intent no link could
    -- have been minted with, which keeps "the session's intent came from a link" true in the
    -- schema rather than only in the handler that copies it.
    CONSTRAINT portal_sessions_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams')),
    CONSTRAINT portal_sessions_digest_is_sha256
        CHECK (octet_length(token_digest) = 32),
    CONSTRAINT portal_sessions_expires_after_created
        CHECK (expires_at > created_at),

    -- ONE SESSION PER LINK, in the schema. The link's own `consumed_at` is what makes redemption
    -- single-use, and this is the second half of that statement: even if a redemption path were
    -- ever written that stamped the link without checking, or checked without stamping, two
    -- sessions from one link would still be refused here. The property #140 asks to have
    -- "verified adversarially" should not rest on one conditional UPDATE alone.
    CONSTRAINT portal_sessions_one_per_link UNIQUE (portal_link_id),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (portal_link_id) REFERENCES portal_links (id)
);

-- ONE INDEX, FOR THE ONE READ THERE IS. `authenticate` looks a session up by digest, on every
-- request, and that is the only query this table serves.
--
-- NO EXPIRY INDEX. The first draft had one, justified as "the sweep reads by expiry" -- and
-- there is no sweep. Nothing purges expired portal sessions today; a row stays in the table
-- after `expires_at` and is simply never matched again. An index maintained on every insert for
-- a reader that does not exist is cost with no benefit, and worse, its comment tells the next
-- operator that reclamation happens. When a sweep is written it can add the index it needs.
CREATE INDEX portal_sessions_digest_idx
    ON portal_sessions (tenant_id, environment_id, token_digest);

ALTER TABLE portal_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_sessions_tenant_isolation ON portal_sessions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE MINTS AND READS THESE, unlike `portal_links` which the CONTROL plane mints.
-- Redemption happens in a browser hitting the data plane, so that is where the session is
-- created and where every subsequent request authenticates against it.
--
-- COLUMN-SCOPED UPDATE, which `the_data_plane_holds_no_table_wide_update_on_any_table` requires
-- and which is right on its own terms: ending a session sets `revoked_at` and nothing else. A
-- table-wide grant would let the data-plane role rewrite the organization or the intent, and
-- those two columns ARE the session's authority.
GRANT SELECT, INSERT ON portal_sessions TO ironauth_app;
GRANT UPDATE (revoked_at) ON portal_sessions TO ironauth_app;
-- THE CONTROL PLANE GETS `SELECT` AND NOTHING ELSE, and the missing grant is the point.
--
-- The first draft also granted `UPDATE (revoked_at)` here, with a comment saying the control
-- plane exists so an operator "can see and end a live portal session". No code performs that
-- write: there is no management route that ends somebody else's portal session, which the
-- `revoked_at` column comment sixty lines above says outright. Two sentences in one file
-- disagreeing about whether a capability exists is worse than either being wrong alone, and a
-- privilege granted for a caller that does not exist is one an operator reading the schema will
-- believe in.
--
-- So the write waits for the surface that performs it. `SELECT` stays because listing live
-- portal sessions is a read an operator surface will want and a read grants nothing on its own:
-- the rows hold digests, never a cookie.
GRANT SELECT ON portal_sessions TO ironauth_control;
