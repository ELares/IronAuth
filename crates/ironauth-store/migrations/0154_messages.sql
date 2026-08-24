-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The outbound message record (issue #111 criteria 1 and 2).
--
-- # What this table is for, and what it is NOT
--
-- `message_prepare::prepare_message` already runs the whole decision pipeline as a PURE
-- function: suppression, rate limit, template resolution, rendering, MIME. It has 129 inline
-- tests across its eleven modules and, until now, zero production callers. Nothing was
-- missing from the decisions. What was missing was a place to WRITE one down and a consumer
-- to deliver it, so this table is the smallest thing that turns that island into a product.
--
-- It is a DELIVERY record, not a message archive. It holds what delivery needs and what an
-- operator needs to answer "did this send, and if not why", and deliberately not the rendered
-- body: a rendered message contains the very secrets the send exists to carry (an OTP code, a
-- magic-link token), and a row that outlives the delivery attempt turns a database read into
-- a credential read. The body is rendered by the consumer, from the template and the
-- variables, at the moment of delivery.
--
-- That has a consequence worth stating here rather than rediscovering at a call site: a
-- message whose only template variable IS the secret cannot use this path at all, because the
-- variables ride a durable outbox payload every consumer worker can read. Such a send has to
-- be delivered inside the request that minted it. No door does that yet; when one arrives it
-- needs a mode this table does not currently offer, not a payload with a code in it.
--
-- # `dedup_key` and why the UNIQUE is the whole point
--
-- `message_hygiene::dedup_key(kind, address, window)` hashes the message kind, the normalized
-- recipient, and a window index. Its own doc says the module cannot answer whether the key has
-- been seen, "because whether this key has been seen inside the window is a store question,
-- and this module cannot answer it". This is the store answering it.
--
-- Criterion 2 asks that a duplicate send inside the window collapse to ONE delivery. A UNIQUE
-- constraint plus `ON CONFLICT DO NOTHING` is that, and it is race-free in a way an
-- application-level check is not: two concurrent requests both reading "no row yet" and both
-- inserting is exactly the shape a SELECT-then-INSERT loses to, and the OTP and magic-link
-- doors are precisely where a user double-clicking produces that race.
--
-- The window is already IN the key, so the constraint carries no time predicate: a send in a
-- later window hashes differently and inserts cleanly. Old rows are pruned by retention
-- rather than by the constraint.

CREATE TABLE messages (
    -- The `msg_` scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The message kind (`email_otp`, `magic_link`, ...). Part of the dedup key, and what
    -- selects the template.
    kind            text        NOT NULL,
    -- The NORMALIZED recipient, as `message_hygiene::normalize_recipient` produced it. Stored
    -- normalized so a listing groups by what the send actually addressed rather than by the
    -- casing a caller happened to pass.
    recipient       text        NOT NULL,
    -- The collapse key: kind + normalized recipient + window index, hashed. See above.
    dedup_key       text        NOT NULL,
    -- Delivery state: `pending` until a consumer resolves it, then `sent` or `failed`.
    state           text        NOT NULL DEFAULT 'pending',
    -- Why a `failed` row failed, for the operator answering "why did this not arrive". NULL
    -- while pending and on success. A CLASSIFICATION, never a provider's raw response: those
    -- carry recipient data and provider-side identifiers.
    failure_reason  text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT messages_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT messages_kind_nonempty CHECK (kind <> ''),
    CONSTRAINT messages_recipient_nonempty CHECK (recipient <> ''),
    CONSTRAINT messages_dedup_key_nonempty CHECK (dedup_key <> ''),
    CONSTRAINT messages_state_known
        CHECK (state IN ('pending', 'sent', 'failed')),
    -- A reason is meaningful only on a failure, and a failure without one is an operator
    -- staring at a state with no answer.
    CONSTRAINT messages_failure_reason_paired
        CHECK ((state = 'failed') = (failure_reason IS NOT NULL)),
    -- CRITERION 2. One delivery per (kind, recipient, window) in a scope.
    UNIQUE (tenant_id, environment_id, dedup_key),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The operator listing: a scope's messages, newest first.
CREATE INDEX messages_scope_idx
    ON messages (tenant_id, environment_id, created_at DESC, id);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
CREATE POLICY messages_tenant_isolation ON messages
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane enqueues a send (INSERT), the delivery consumer resolves it (SELECT, and
-- UPDATE of exactly the two columns a resolution writes). Column-scoped UPDATE for the issue
-- #31 reason every table here follows: a table-wide grant auto-extends to every column added
-- later, including the recipient and the dedup key, and a plane that can rewrite a dedup key
-- can replay a suppressed send.
GRANT SELECT, INSERT ON messages TO ironauth_app;
GRANT UPDATE (state, failure_reason, updated_at) ON messages TO ironauth_app;

-- The CONTROL plane reads for the operator listing and nothing else: a management surface
-- that could enqueue a send could use the product as a mailer.
GRANT SELECT ON messages TO ironauth_control;
