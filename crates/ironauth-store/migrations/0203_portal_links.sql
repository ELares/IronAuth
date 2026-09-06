-- The self-service admin portal's entry link (issue #140).
--
-- WHAT IT IS. A vendor's backend calls the management API and gets back a short-lived, single-use
-- URL to hand their customer's IT admin. Following it opens a portal session bound to EXACTLY
-- ONE organization and ONE intent -- configure SSO, or SCIM, or verify a domain, or set up log
-- streams -- and the session can reach nothing else. The whole point of the product is that the
-- vendor does nothing further, so the link is the only authority the admin ever holds and every
-- boundary the portal has is a property of this row.
--
-- A DIGEST, NEVER THE TOKEN. `token_digest` is SHA-256 of a high-entropy CSPRNG value that exists
-- only in the URL handed to the vendor; the row cannot mint the link that satisfies it. This is
-- the same digest-only single-use pattern as `magic_link_tokens` (migration 0048), and it is used
-- here for the same reason: whoever can read this table cannot then walk into a customer's
-- organization.
--
-- INTENT IS A COLUMN, NOT A CLAIM IN THE TOKEN. #140 requires that an `sso` link cannot reach
-- SCIM or domain-verification surfaces, "verified adversarially". Putting the intent in the token
-- would make it a value the holder presents; putting it here makes it a value the server looks
-- up, so widening it needs a write an admin has no path to. The organization is here for the
-- identical reason -- a portal session for org A must not read or mutate org B state, and that is
-- decided by this row rather than by anything the browser carries.
--
-- `consumed_at` IS SET BY A POST, NOT BY THE GET THAT OPENS THE PAGE, and the handler enforces
-- that. An IT admin receives this link by email, and enterprise mail scanners follow links: a
-- link burned on GET would be dead before its recipient clicked it, which is the failure 0048
-- already documents for magic links. The GET renders a confirmation; the POST redeems.
CREATE TABLE portal_links (
    -- The plk_ scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The ONE organization a session opened from this link may see.
    organization_id   text        NOT NULL,
    -- The ONE surface it may reach. A closed set: an unknown intent can never be written, so a
    -- handler matching on it has no arm to guess at.
    intent            text        NOT NULL,
    -- SHA-256 of the bearer value in the URL. Never the value itself.
    token_digest      bytea       NOT NULL,
    -- NO `created_by` COLUMN. Who asked for the link is already the actor on the
    -- `portal_link.mint` audit row this insert writes in the same transaction, and a second copy
    -- here would be one fact with two homes that nothing keeps in step.
    created_at        timestamptz NOT NULL,
    -- The TTL horizon. #140 asks for five minutes by default; the column holds whatever the
    -- caller asked for so the default can move without a migration.
    expires_at        timestamptz NOT NULL,
    -- Set exactly once, by the POST that opens a session.
    consumed_at       timestamptz,

    CONSTRAINT portal_links_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT portal_links_id_shape
        CHECK (id <> '' AND octet_length(id) <= 256),
    -- The closed intent set (issue #140's minimum). Adding one is a migration, which is the
    -- point: a new portal surface cannot be reached until somebody has written down that it
    -- exists.
    CONSTRAINT portal_links_intent_known
        CHECK (intent IN ('sso', 'scim', 'domain-verification', 'log-streams')),
    -- EXACTLY 32 BYTES. A shorter value is not a SHA-256 digest, and accepting one would let a
    -- caller store a truncated comparison that is cheaper to collide.
    CONSTRAINT portal_links_digest_is_sha256
        CHECK (octet_length(token_digest) = 32),
    CONSTRAINT portal_links_expires_after_created
        CHECK (expires_at > created_at),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The sweep reads by expiry; the redeem reads by id (the primary key).
CREATE INDEX portal_links_expiry_idx
    ON portal_links (tenant_id, environment_id, expires_at);

ALTER TABLE portal_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_links FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_links_tenant_isolation ON portal_links
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE REDEEMS, so it needs UPDATE -- unlike most tables here, where it only reads.
-- The redemption is a conditional UPDATE that sets `consumed_at` exactly once, which is what
-- makes the link single-use under concurrency; a read-then-write in the handler would admit two
-- sessions from one link. The CONTROL plane mints.
--
-- COLUMN-SCOPED, WHICH THE #31 LESSON REQUIRES AND A TEST ENFORCES: a table-wide UPDATE would
-- let the data-plane role rewrite the organization, the intent or the digest -- the three values
-- that ARE the link's authority -- and redeeming needs none of them. It needs to stamp
-- `consumed_at`. `migration.rs::the_data_plane_holds_no_table_wide_update_on_any_table` reads
-- `information_schema.table_privileges` and fails on the table-wide form, which is how the first
-- draft of this grant was caught.
GRANT SELECT ON portal_links TO ironauth_app;
GRANT UPDATE (consumed_at) ON portal_links TO ironauth_app;
GRANT SELECT, INSERT ON portal_links TO ironauth_control;
