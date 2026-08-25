-- Suppressed recipients (issue #111 criterion 6).
--
-- "Sends to suppressed addresses are blocked and recorded with a queryable reason." The
-- decision of WHEN an address becomes suppressed already exists, pure and tested, in
-- `message_feedback::suppression_action`: a hard bounce suppresses immediately, a complaint
-- suppresses immediately, and repeated soft bounces suppress on the third. What was missing was
-- somewhere to write the answer down and something that reads it before a send.
--
-- # Why an address is suppressed, and why the reason is a column
--
-- A suppression is not a preference, it is a promise. Continuing to mail an address that hard
-- bounced burns the sending domain's reputation for every other tenant on it, and continuing to
-- mail an address that filed a complaint is the behaviour that gets a sender blocklisted. The
-- REASON has to be queryable because the operator's question is never "is this suppressed", it
-- is "why is my user not getting mail", and an answer of "it is suppressed" ends that
-- conversation without resolving it.
--
-- # The recipient is a blind index, for the reason it is one on `messages`
--
-- Same construction, same per-tenant keyed HMAC, its own label. A suppression list is a list of
-- people who have complained about or failed to receive mail, which is exactly the kind of list
-- that must not be a plaintext directory of addresses sitting in a table. Equality is all this
-- table needs, and equality is what a blind index gives.
CREATE TABLE message_suppressions (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The recipient blind index: a deterministic per-tenant keyed HMAC of the normalized
    -- address, never the plaintext. See `messages.recipient_bidx`.
    recipient_bidx  bytea       NOT NULL,
    -- Why this address is suppressed. A CLASSIFICATION an operator groups by, never a
    -- provider's raw response: those carry recipient data and provider-side identifiers.
    reason          text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT message_suppressions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT message_suppressions_recipient_nonempty
        CHECK (octet_length(recipient_bidx) > 0),
    CONSTRAINT message_suppressions_reason_known
        CHECK (reason IN ('hard_bounce', 'complaint', 'repeated_soft_bounce', 'manual')),

    -- One suppression per recipient per scope. A second hard bounce does not make an address
    -- more suppressed, and two rows would make "why" ambiguous.
    PRIMARY KEY (tenant_id, environment_id, recipient_bidx),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE message_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_suppressions FORCE ROW LEVEL SECURITY;
CREATE POLICY message_suppressions_tenant_isolation ON message_suppressions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane reads it before every send and writes it when a provider reports a bounce or
-- a complaint.
--
-- NO DELETE, deliberately, and it is a gap rather than a decision. Un-suppressing a recipient
-- who fixed their mailbox is an ordinary support action and this table will need it. But the
-- operation does not exist yet, and the migration test that guards the DELETE grant set says
-- plainly what to do about that: name the caller in the migration, or do not take the grant.
-- A privilege held by nobody is one an attacker inherits for free, so it arrives with its
-- caller.
GRANT SELECT, INSERT ON message_suppressions TO ironauth_app;

-- The CONTROL plane reads for the operator answering "why is my user not getting mail". It may
-- NOT insert: a management surface that could suppress an address could silence a competitor's
-- users on a shared deployment.
GRANT SELECT ON message_suppressions TO ironauth_control;
