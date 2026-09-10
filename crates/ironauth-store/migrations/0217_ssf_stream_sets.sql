-- Shared Signals: the SETs a stream owes its receiver (issue #143).
--
-- One row is one Security Event Token that has been minted for one stream and not yet
-- acknowledged. RFC 8936 poll delivery needs exactly this: a poll receiver COLLECTS from the
-- transmitter, so the transmitter has to hold what it owes until the receiver says it has it.
--
-- THE SIGNED TOKEN IS STORED, not the ingredients to re-mint one. RFC 8936 section 2.2 has an
-- unacknowledged SET redelivered on the next poll, and a receiver comparing two deliveries of
-- one event must see the same token: re-minting would restamp `iat` and change the JWS while
-- the `jti` stayed put, which is a difference a receiver cannot explain. It also means a key
-- rotation between mint and collection cannot strand a SET the receiver already half-processed.
--
-- IT IS ALSO WHAT A PAUSED PUSH STREAM NEEDS. 0216 documents `paused` as the state that RETAINS
-- events, and the push consumer implements that hold on the outbox's finite retry budget, which
-- discards the oldest events of a long pause (issue #1197). This table is the durable place
-- that belongs to; wiring push through it is that issue's, not this migration's.
--
-- BOUNDED, because a receiver that never polls must not grow without limit. Two bounds, and
-- they answer different failures: `ssf_stream_sets_jws_bounded` stops one enormous token, and
-- the per-stream count the surface enforces stops a slow receiver accumulating forever. A
-- deployment reaching either has a receiver that has stopped collecting, which is a fact an
-- operator wants surfaced rather than absorbed.

CREATE TABLE ssf_stream_sets (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The stream that owes it. CASCADE: a receiver that deletes its stream is owed nothing, and
    -- the tokens describe that receiver's subjects, so keeping them would be retaining PII for
    -- a delivery that can never happen.
    stream_id      text        NOT NULL,
    -- The SET's `jti`, which is also what the receiver acknowledges by. Minted once by the
    -- producer, so a redelivery and an acknowledgement name the same thing.
    jti            text        NOT NULL,
    -- The compact JWS, exactly as it will be handed to the receiver.
    set_jws        text        NOT NULL,
    -- When it was queued. The poll returns oldest first, so a receiver draining a backlog gets
    -- its events in the order they happened.
    queued_at      timestamptz NOT NULL DEFAULT now(),

    -- ONE ROW PER (STREAM, EVENT). The producer's `jti` is unique per event per stream, so a
    -- re-enqueue of one event is a conflict rather than a second copy the receiver would
    -- collect twice.
    PRIMARY KEY (tenant_id, environment_id, stream_id, jti),

    CONSTRAINT ssf_stream_sets_jti_shaped
        CHECK (btrim(jti) <> '' AND octet_length(jti) <= 252),
    -- A compact JWS three segments long, and bounded: a SET carrying an event payload larger
    -- than this is a producer defect, and storing it would let one event fill a receiver's
    -- queue.
    CONSTRAINT ssf_stream_sets_jws_bounded
        CHECK (octet_length(set_jws) BETWEEN 1 AND 16384),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (stream_id) REFERENCES ssf_streams (id) ON DELETE CASCADE
);

-- The poll reads one stream's oldest unacknowledged tokens; the retention sweep reads by age.
CREATE INDEX ssf_stream_sets_by_stream_idx
    ON ssf_stream_sets (tenant_id, environment_id, stream_id, queued_at, jti);

ALTER TABLE ssf_stream_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_stream_sets FORCE ROW LEVEL SECURITY;

CREATE POLICY ssf_stream_sets_scope ON ssf_stream_sets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE OWNS IT, exactly as it owns `ssf_streams` (0216): the receiver polls and
-- acknowledges on a request path, so the role that serves requests is the role that reads and
-- deletes. DELETE is the acknowledgement -- an acknowledged SET is one the transmitter no
-- longer owes, and what it CONTAINED is a security event about a subject, which is not data to
-- keep after delivery.
--
-- NO UPDATE, and that is the point: a stored SET is immutable. The token a receiver collects on
-- its second poll is byte-identical to the one it collected on its first, which is what makes a
-- redelivery indistinguishable from the original.
GRANT SELECT, INSERT, DELETE ON ssf_stream_sets TO ironauth_app;
-- The CONTROL plane reads them: an operator asking why a receiver is behind wants the depth.
GRANT SELECT ON ssf_stream_sets TO ironauth_control;
