-- Shared Signals Framework: the stream (issue #143).
--
-- One row is one RECEIVER's standing subscription to this environment's security events. SSF
-- 1.0 calls it a stream; RFC 8935 and RFC 8936 are the two ways its Security Event Tokens
-- reach the receiver. The SETs themselves, their queueing and their delivery land in later
-- slices; this is the configuration all of them read, and it comes first because everything
-- else is a consumer of it.
--
-- PER RECEIVER, not per organization, and that is the difference from every other connector
-- table here. A stream is created BY the receiver through an OAuth-protected endpoint on the
-- public plane, so the principal that owns it is the client whose credential created it, and
-- `client_id` is what every RECEIVER-FACING read and every write is fenced on. #143 states the
-- rule directly: "a receiver's credentials grant access to exactly its own streams". A stream
-- reachable by a second RECEIVER is the IDOR this column exists to make unrepresentable.
--
-- ONE READ IS DELIBERATELY NOT FENCED, and saying so here is the point. The fan-out that turns
-- an environment's security events into SETs reads every retaining stream in the scope, because
-- that is what a fan-out is: it acts for the environment, not for any client, so it takes no
-- `client_id` -- which is also what keeps it from being mistaken for a read a receiver can
-- reach. Nothing a receiver can call reaches it.
--
-- THE PUSH CREDENTIAL IS NOT A COLUMN. `push_secret_name` names an `environment_secrets` row,
-- the way 0212 and 0189 do, and the value is resolved at delivery time through the sealing
-- path that already exists. A second sealed column is a second sealing path to get right, and
-- naming the secret gives rotation for free.
--
-- NO DELIVERY STATE HERE. What was sent, what was acknowledged, and what is owed belong to the
-- SET and to the queue, not to the configuration. Putting a cursor on this row would make
-- every delivery write contend with every configuration read, which is the reason 0212 gives
-- for keeping sync state off the connector.

CREATE TABLE ssf_streams (
    -- The `sst_` scoped identifier; embeds its (tenant, environment).
    id                    text        NOT NULL PRIMARY KEY,
    tenant_id             text        NOT NULL,
    environment_id        text        NOT NULL,

    -- THE RECEIVER. The OAuth client whose credential created this stream, and the only
    -- principal permitted to read, update, or delete it.
    client_id             text        NOT NULL,

    -- The SSF 1.0 stream-status vocabulary, cited by NAME rather than by section number: an
    -- earlier draft of this file cited "section 7.1.2", which is not where the status vocabulary
    -- lives, and a number nobody checked is worse than no number.
    --
    -- `enabled` delivers; `paused` RETAINS events without delivering them, which is the state a
    -- receiver asks for during its own maintenance; `disabled` delivers nothing and retains
    -- nothing. The difference between the two non-delivering states is what a receiver gets back
    -- when it resumes, so they cannot be collapsed.
    status                text        NOT NULL DEFAULT 'enabled',
    -- Why it is in that state, when a transmitter set it (SSF 1.0 allows a reason). NULL when
    -- the receiver set the state itself and gave none.
    status_reason         text,

    -- HOW SETS REACH THE RECEIVER: the RFC that defines the method, spelled as SSF 1.0 spells
    -- it. Push (8935) means we POST to the receiver; poll (8936) means the receiver fetches
    -- from us. The URN rather than a local word, because it is what the stream configuration
    -- publishes back and what discovery advertises -- a local spelling would be a second
    -- vocabulary free to drift from the one on the wire.
    delivery_method       text        NOT NULL,
    -- PUSH ONLY. The receiver's endpoint, a customer-supplied URL: every POST to it goes
    -- through the SSRF-hardened fetcher (issue #10). NULL for a poll stream, and the CHECK
    -- below makes the pairing structural rather than conventional.
    push_endpoint_url     text,
    -- PUSH ONLY, OPTIONAL. Names an `environment_secrets` row holding the bearer the receiver
    -- wants presented on delivery. NULL means the receiver authenticates our SETs by their
    -- SIGNATURE alone, which RFC 8935 permits and which is the honest default: the signature
    -- is the authentication, a bearer is at most a second gate.
    push_secret_name      text,

    -- THE NEGOTIATION, both halves kept. `events_requested` is what the receiver ASKED for and
    -- `events_delivered` is what this transmitter agreed to send: SSF 1.0 requires both to be
    -- readable back, because a receiver that asked for an event this transmitter does not
    -- support must be able to SEE that it is not coming. Storing only the intersection would
    -- answer "you asked for exactly what you are getting", which is the one thing it must
    -- never say when that is false.
    events_requested      jsonb       NOT NULL,
    events_delivered      jsonb       NOT NULL,

    -- RFC 9493. The identifier format a subject is rendered in for THIS stream, negotiated per
    -- stream because receivers genuinely differ: one keys its users by email, another by the
    -- (issuer, subject) pair, another by an opaque handle it was given.
    subject_format        text        NOT NULL DEFAULT 'iss_sub',

    -- The `aud` every SET on this stream carries, per SSF 1.0's stream configuration. An array,
    -- because the claim permits one or many and a receiver fronting several audiences is
    -- ordinary.
    audience              jsonb       NOT NULL,
    -- What the receiver calls it. Operator-facing only; nothing keys on it.
    description           text,

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ssf_streams_status_known
        CHECK (status IN ('enabled', 'paused', 'disabled')),
    CONSTRAINT ssf_streams_status_reason_shaped
        CHECK (status_reason IS NULL
               OR (btrim(status_reason) <> '' AND octet_length(status_reason) <= 252)),
    CONSTRAINT ssf_streams_delivery_method_known
        CHECK (delivery_method IN ('urn:ietf:rfc:8935', 'urn:ietf:rfc:8936')),
    -- THE PAIRING, structural. A push stream without an endpoint has nowhere to deliver and a
    -- poll stream with one names an address nothing reads -- and a poll stream that carried a
    -- push URL would be one code path away from delivering to it. Both halves are stated, so
    -- neither shape can be written.
    CONSTRAINT ssf_streams_push_endpoint_pairs_with_method
        CHECK ((delivery_method = 'urn:ietf:rfc:8935') = (push_endpoint_url IS NOT NULL)),
    CONSTRAINT ssf_streams_push_endpoint_shaped
        CHECK (push_endpoint_url IS NULL
               OR (push_endpoint_url LIKE 'https://%' AND octet_length(push_endpoint_url) <= 2048)),
    -- A SECRET ONLY A PUSH STREAM CAN NAME. A poll stream presents nothing outbound, so a
    -- credential on one is a credential nothing uses and nobody can account for.
    CONSTRAINT ssf_streams_push_secret_needs_push
        CHECK (push_secret_name IS NULL OR delivery_method = 'urn:ietf:rfc:8935'),
    CONSTRAINT ssf_streams_push_secret_shaped
        CHECK (push_secret_name IS NULL
               OR (btrim(push_secret_name) <> '' AND octet_length(push_secret_name) <= 252)),
    -- BOTH HALVES ARE ARRAYS. `jsonb_typeof` is checked rather than assumed because the column
    -- is read back into the stream configuration document: an object here would serialize as
    -- an object and publish a malformed SSF response.
    CONSTRAINT ssf_streams_events_requested_is_array
        CHECK (jsonb_typeof(events_requested) = 'array'),
    CONSTRAINT ssf_streams_events_delivered_is_array
        CHECK (jsonb_typeof(events_delivered) = 'array'),
    -- DELIVERED IS A SUBSET OF REQUESTED. A transmitter may narrow what a receiver asked for;
    -- it may never widen it. Without this the negotiation could publish an event type the
    -- receiver never asked to receive, which is the one direction SSF 1.0 forbids.
    CONSTRAINT ssf_streams_delivered_within_requested
        CHECK (events_delivered <@ events_requested),
    -- The RFC 9493 formats this transmitter renders. #143 requires at least these three.
    CONSTRAINT ssf_streams_subject_format_known
        CHECK (subject_format IN ('email', 'iss_sub', 'opaque')),
    CONSTRAINT ssf_streams_audience_is_nonempty_array
        CHECK (jsonb_typeof(audience) = 'array' AND jsonb_array_length(audience) > 0),
    CONSTRAINT ssf_streams_description_shaped
        CHECK (description IS NULL
               OR (btrim(description) <> '' AND octet_length(description) <= 252)),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- THE COMPOSITE REFERENCE, not `clients (id)`. It pins the receiver to the SAME
    -- (tenant, environment) as the stream, so a client id from another scope cannot be
    -- written here at all. 0017 and 0177 use the same three-column form for the same
    -- reason; the two-column form elsewhere leaves that agreement to the application.
    FOREIGN KEY (client_id, tenant_id, environment_id)
        REFERENCES clients (id, tenant_id, environment_id)
);

-- A receiver lists ITS OWN streams, which is the only listing the surface offers.
-- THE SORT COLUMNS ARE PART OF THE INDEX, the rule 0189 states and credits 0183 for: the
-- listing orders by `(created_at, id)` and resumes from that pair, so without them the index
-- serves the filter and leaves every page to a sort over all of the receiver's rows.
CREATE INDEX ssf_streams_by_client_idx
    ON ssf_streams (tenant_id, environment_id, client_id, created_at, id);
-- The fan-out reads every stream that RETAINS an event generated now, which is both 'enabled'
-- and 'paused' -- a paused stream accumulates, and one omitted here is a backlog its receiver
-- can never be given. The partial predicate therefore matches `SsfStreamStatus::retains`
-- rather than `delivers`; an index on 'enabled' alone would not serve that read, and the
-- planner would fall back to a scan while the code above claimed otherwise.
CREATE INDEX ssf_streams_retaining_idx
    ON ssf_streams (tenant_id, environment_id) WHERE status <> 'disabled';

ALTER TABLE ssf_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_streams FORCE ROW LEVEL SECURITY;

CREATE POLICY ssf_streams_scope ON ssf_streams
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE OWNS THIS ONE, which is the difference from 0212. A stream is created and
-- managed by a RECEIVER on the public plane, on a request path, so the role that serves
-- requests is the role that writes it. DELETE is granted because SSF 1.0 gives the receiver a
-- delete: a stream row records no history worth keeping -- what it DELIVERED is in the SETs
-- and in the audit log, neither of which this row owns.
GRANT SELECT, INSERT, DELETE ON ssf_streams TO ironauth_app;
-- UPDATE is column-scoped to exactly what the ONE update statement in the tree writes.
-- `ActingSsfStreamRepo::set_status` writes these three and there is no other; the columns
-- withheld are the ones that decide WHOSE stream this is and WHERE it delivers, so no update
-- can re-point a stream at another receiver's endpoint.
--
-- The configuration update SSF 1.0 also defines is a later slice, and its columns are granted
-- with the statement that writes them rather than ahead of it. 0212 states the rule this
-- follows: "A privilege for a write nothing performs is one nobody can account for later."
-- That matters more here than usual, because this file is checksummed whole-file once applied
-- -- a grant justified by an operation that does not exist could never have its justification
-- corrected, only revoked by a later migration contradicting prose nobody can edit.
GRANT UPDATE (status, status_reason, updated_at) ON ssf_streams TO ironauth_app;
-- The CONTROL plane reads them: the operator console lists an environment's streams, and the
-- fan-out that turns a session-ended event into SETs runs there.
GRANT SELECT ON ssf_streams TO ironauth_control;
