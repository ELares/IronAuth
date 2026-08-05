-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-attempt webhook delivery history (issue #106).
--
-- Before this, a failed delivery left exactly two facts behind: a counter on the queue row
-- and the label of the MOST RECENT failure. An operator asking the only question that
-- matters when a webhook stops arriving, which is "what did my endpoint actually answer,
-- and when", had nothing to read. This is that record: one row per attempt, carrying the
-- status the receiver returned, how long it took, and the failure label.
--
-- ## Bounded by construction, not by a reaper
--
-- Migration 0099 shipped `outbox_messages` with no retention of any kind and 0102 had to
-- add a sweeper afterwards. A per-ATTEMPT table grows faster than the message table it
-- describes, so the same mistake here would be worse, and it is avoided structurally
-- rather than by adding a second reaper to keep in step with the first.
--
-- The foreign key to `outbox_messages` with ON DELETE CASCADE ties an attempt's lifetime
-- to the message it describes. The outbox retention sweeper (0102) is therefore the ONLY
-- retention control: when it reaps a completed or dead-lettered message, that message's
-- attempts go with it, in the same statement, under whatever retention the operator has
-- already configured. There is no second knob to set, no second sweeper to run, and no way
-- for the two to disagree about how long history is kept.
--
-- A referential action runs with the privileges of the constraint rather than the caller,
-- so the cascade needs no DELETE grant on this table for the role that reaps.
--
-- ## What is NOT stored
--
-- The response BODY. The issue asks for a truncated one, and it is deliberately left out
-- of this migration: a webhook receiver's error body is arbitrary text from outside the
-- trust boundary that could carry anything its author put there, including credentials
-- echoed back from the request. Storing it needs a redaction decision this table does not
-- have to make in order to be useful, and `status_code` plus `error` answer the debugging
-- question in almost every case. `error` holds the same bounded, non-secret labels the
-- queue's `last_error` does and nothing derived from a response.
CREATE TABLE webhook_delivery_attempts (
    id               text        PRIMARY KEY,
    tenant_id        text        NOT NULL,
    environment_id   text        NOT NULL,
    -- The endpoint the attempt was made against. Not a foreign key to webhook_endpoints:
    -- deleting an endpoint must not erase the record of what was delivered to it, which is
    -- the same reason an audit row outlives its subject.
    endpoint_id      text        NOT NULL,
    -- The queue message this attempt was for. CASCADE is the retention mechanism above.
    message_id       text        NOT NULL
        REFERENCES outbox_messages (id) ON DELETE CASCADE,
    -- The `webhook-id` header the attempt carried. Denormalized from the message's
    -- idempotency key so a history read needs no join, and because it is the value a
    -- consumer deduplicated on and therefore the one an operator correlates by.
    webhook_id       text        NOT NULL,
    -- Which attempt this was, starting at 1, so the history reads in order even if two
    -- attempts share a timestamp at the clock's resolution.
    attempt_number   integer     NOT NULL CHECK (attempt_number >= 1),
    attempted_at     timestamptz NOT NULL,
    -- NULL when the delivery never reached a response at all (a refused destination, a
    -- timeout, a transport fault). A status is what the RECEIVER said; its absence is
    -- itself the useful fact, and `error` names which of those it was.
    status_code      integer     CHECK (status_code IS NULL
                                        OR (status_code >= 100 AND status_code <= 599)),
    -- Round-trip duration in milliseconds, measured across the send through the clock
    -- seam. Never negative.
    latency_ms       bigint      NOT NULL CHECK (latency_ms >= 0),
    -- NULL on a success. Otherwise the same bounded, non-secret label the queue records.
    error            text
);

-- The read this table exists for: one endpoint's history, newest first. Scope leads
-- because every read is scoped, and `attempted_at DESC` matches the order the listing
-- returns so the index serves the sort as well as the filter.
CREATE INDEX webhook_delivery_attempts_by_endpoint
    ON webhook_delivery_attempts (tenant_id, environment_id, endpoint_id, attempted_at DESC);

-- The cascade's own lookup. Without it, reaping a batch of messages scans this table once
-- per deleted row, which turns retention into the slowest statement in the system exactly
-- when the backlog is largest.
CREATE INDEX webhook_delivery_attempts_by_message
    ON webhook_delivery_attempts (message_id);

ALTER TABLE webhook_delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_attempts_tenant_isolation ON webhook_delivery_attempts
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane writes history, because it is the plane that makes the attempts. It gets
-- INSERT and SELECT and nothing else: an attempt is a fact about something that already
-- happened, so nothing may edit one, and a role that could rewrite its own delivery record
-- could hide a failure it caused.
GRANT SELECT, INSERT ON webhook_delivery_attempts TO ironauth_app;

-- The CONTROL plane only reads: the management history surface is a listing. It is given
-- no DELETE either, so the cascade above stays the single retention path and an operator
-- cannot erase one endpoint's failure record while leaving its messages behind.
GRANT SELECT ON webhook_delivery_attempts TO ironauth_control;
