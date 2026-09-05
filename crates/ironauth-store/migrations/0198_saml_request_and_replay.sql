-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The two tables that make a SAML response ONE-TIME (issue #139).
--
-- Both exist to refuse a replay, from opposite directions, and #139 names both as CVE classes.
--
-- `saml_outstanding_requests` is the CVE-2026-9098 defence: a response carries `InResponseTo`,
-- and unless it names a request THIS deployment issued and has not yet consumed, it is refused.
-- That is what makes a captured response useless a second time, and what makes a response
-- nobody asked for useless the first.
--
-- `saml_assertion_replay` is what stands in for it when an operator opts into IdP-initiated
-- sign-in. There is no request to correlate then, so the assertion's own ID is remembered for
-- its full validity window instead. It is the weaker defence, which is why the opt-in also
-- bounds that window.

-- An AuthnRequest this deployment issued and is waiting for an answer to.
CREATE TABLE saml_outstanding_requests (
    -- THE AuthnRequest ID ITSELF, which is what `InResponseTo` will carry. It is the natural key,
    -- and making it the primary key is what makes redemption a single conditional UPDATE rather
    -- than a read followed by a write.
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    connection_id       text        NOT NULL,

    -- Where the browser goes after a successful sign-in. Opaque to this table.
    relay_state         text,

    -- BOUND BY THE CALLER, from the application clock seam, and not defaulted to `now()`.
    --
    -- The constraint below compares this against `expires_at`, which the caller computes from
    -- that same seam. Defaulting one side to the DATABASE clock puts two clocks on either side of
    -- one comparison: they agree in production and disagree under the manual clock this
    -- deployment's tests use, so a deliberate expiry becomes an unwritable row and the case
    -- cannot be exercised at all. Every other timestamp this system reasons about comes from the
    -- seam for the same reason.
    created_at          timestamptz NOT NULL,
    -- After this, no response naming it is accepted, whatever the assertion's own conditions say.
    -- A separate bound from the assertion's, and the shorter of the two wins: an identity
    -- provider that asserts a twelve-hour validity does not get a twelve-hour window here.
    expires_at          timestamptz NOT NULL,
    -- ONE-TIME USE. Set by the redemption, and the redemption is `WHERE consumed_at IS NULL`, so
    -- two concurrent responses naming one request produce exactly one winner without a lock.
    consumed_at         timestamptz,

    CONSTRAINT saml_outstanding_requests_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT saml_outstanding_requests_id_bounded
        CHECK (id <> '' AND octet_length(id) <= 256),
    -- BOUNDED, because it round-trips through a browser and comes back. SAML 2.0 Bindings
    -- section 3.4.3 puts the limit at 80 bytes for the Redirect binding; this is generous
    -- against that and finite, which is the property that matters for a column.
    CONSTRAINT saml_outstanding_requests_relay_state_bounded
        CHECK (relay_state IS NULL OR octet_length(relay_state) <= 1024),
    CONSTRAINT saml_outstanding_requests_expires_after_creation
        CHECK (expires_at > created_at),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (connection_id) REFERENCES saml_connections (id) ON DELETE CASCADE
);

-- The sweep that removes expired rows, and the only query besides the keyed redemption.
CREATE INDEX saml_outstanding_requests_by_expiry
    ON saml_outstanding_requests (tenant_id, environment_id, expires_at);

ALTER TABLE saml_outstanding_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_outstanding_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_outstanding_requests_scope ON saml_outstanding_requests
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE OWNS THIS ONE, unlike the connection and its pins. Issuing an AuthnRequest and
-- consuming the response are both sign-in, and sign-in runs on the data plane.
--
-- UPDATE is column scoped to `consumed_at`, which is the only column any statement writes after
-- the insert. A row cannot have its expiry extended or its connection changed under a handle
-- that keeps its id.
--
-- NO DELETE GRANT. Both these tables need an expiry sweep and neither has one yet: a grant for a
-- write nothing performs is a permission nobody can account for, which is the rule 0189 states
-- and which its first version broke. The grant arrives with the sweep, in the migration that adds
-- it, so this one cannot be read as having already permitted it.
--
-- Until then the rows accumulate, which is a table that grows and not a correctness problem: a
-- consumed request is refused by `consumed_at IS NOT NULL` and an expired one by `expires_at`,
-- whether or not the row is still there.
GRANT SELECT, INSERT ON saml_outstanding_requests TO ironauth_app;
GRANT UPDATE (consumed_at) ON saml_outstanding_requests TO ironauth_app;

-- An assertion already seen, for a connection that accepts unsolicited responses.
CREATE TABLE saml_assertion_replay (
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    connection_id       text        NOT NULL,
    -- The assertion's own `ID` attribute.
    assertion_id        text        NOT NULL,
    -- From the application clock seam, like `saml_outstanding_requests.created_at` and for the
    -- same reason: it is compared against `expires_at`, which comes from there.
    seen_at             timestamptz NOT NULL,
    -- WHEN THE ROW COULD SAFELY BE FORGOTTEN, and NOTHING READS IT YET.
    --
    -- The check is the primary key, so an assertion is refused for as long as its row exists --
    -- which, with no sweep, is for ever. That is strictly SAFER than the window this column
    -- describes and it is not what an operator would expect from the column's name, so the
    -- discrepancy is written down rather than left to be discovered.
    --
    -- It is recorded now because the sweep needs it and because it is knowable only here, at
    -- admission: the assertion's own `NotOnOrAfter`, bounded by the connection's
    -- `max_assertion_age_secs`. Reconstructing it later would mean keeping the assertion.
    expires_at          timestamptz NOT NULL,

    -- THE INSERT IS THE CHECK. A composite primary key makes a duplicate a unique violation
    -- inside the transaction that is admitting the assertion, so two concurrent redemptions of
    -- one assertion admit exactly one -- which is the property #139 asks to be proven under
    -- concurrency, and it cannot be got from a read-then-write.
    PRIMARY KEY (tenant_id, environment_id, connection_id, assertion_id),

    CONSTRAINT saml_assertion_replay_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT saml_assertion_replay_assertion_id_bounded
        CHECK (assertion_id <> '' AND octet_length(assertion_id) <= 256),
    CONSTRAINT saml_assertion_replay_expires_after_seen
        CHECK (expires_at > seen_at),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (connection_id) REFERENCES saml_connections (id) ON DELETE CASCADE
);

CREATE INDEX saml_assertion_replay_by_expiry
    ON saml_assertion_replay (tenant_id, environment_id, expires_at);

ALTER TABLE saml_assertion_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_assertion_replay FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_assertion_replay_scope ON saml_assertion_replay
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- NO UPDATE, and its absence is the design. A row here is a fact that an assertion was seen. A
-- grant to change `expires_at` would be a grant to shorten a replay window from inside the
-- request that is using it.
--
-- NO DELETE either, for the same reason as the table above: the sweep does not exist yet, and its
-- grant belongs with it.
--
-- AND THE CHECK DOES NOT READ `expires_at`. An earlier version of this line said it did, which
-- contradicts the column's own note forty lines up: the check is the PRIMARY KEY, so an assertion
-- is refused for as long as its row exists, and with no sweep that is for ever. Strictly safer
-- than the window the column describes, and not what the column's name suggests, which is why
-- both places now say so.
GRANT SELECT, INSERT ON saml_assertion_replay TO ironauth_app;
