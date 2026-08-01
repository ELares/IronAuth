-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The generic transactional outbox and lease based job queue (issue #104, PR 1).
--
-- Every outbound subsystem this milestone adds (webhook delivery, back-channel logout
-- delivery, SIEM sinks, migration jobs, notification fan-out) needs the same three
-- things: a row that commits with the domain write that caused it, a queue several
-- workers can drain at once without double processing, and a bounded retry that ends in
-- a dead letter rather than in an infinite redelivery loop. Two tables already do parts
-- of this and neither does all of it:
--
--   session_ended_events (0024) has the transactional enqueue, the FOR UPDATE SKIP
--     LOCKED claim, and the visibility lease, and has NO attempts counter, NO backoff
--     gate, and NO dead-letter state, so a consumer that keeps failing redelivers
--     forever;
--   backchannel_logout_deliveries (0025) has the attempts counter, the next_attempt_at
--     backoff gate, and the dead-letter marker, and is welded to ONE recipient shape
--     (an event exploded per relying party, carrying a logout URI and a jti).
--
-- This table is their UNION with the two things neither needed and every later consumer
-- does: a CONSUMER discriminator, so one queue serves many independent drains, and an
-- ORDERING KEY, so the messages of one aggregate are delivered in the order they were
-- enqueued instead of racing each other across a worker pool.
--
-- WHAT THE ORDERING KEY BUYS, AND WHAT IT COSTS
--
-- The schema's half of the ordering rule is that the claim can enforce it structurally: a
-- row is claimable only when NO non-terminal row of its group has a LOWER sequence, so of
-- the rows VISIBLE to a claim at most one per group is ever eligible and the group
-- advances one message at a time.
--
-- That is a statement about claims, and it becomes a statement about ORDER only when the
-- sequences it compares were assigned in the order the producers intended. See the
-- OutboxConsumer trait documentation for the exact guarantee and for the producer
-- precondition the strong form needs; do not restate a stronger version of it here. The
-- schema's contribution is the partial index below that makes the head-of-group test an
-- index probe rather than a scan.
--
-- The cost is real and is the reason ordering_key is per MESSAGE rather than a property
-- of the consumer. A group's head BLOCKS its group: a message that keeps failing holds
-- its aggregate until the attempts cap dead-letters it, which is exactly why the cap
-- must be finite. Parallelism within a consumer is bounded by the number of distinct
-- ordering keys with due work, not by the worker count. A consumer that does not need
-- ordering sets ordering_key to something unique per message (its own idempotency key
-- is the obvious choice), which makes every group a singleton and removes the blocking
-- entirely.
--
-- WHAT THIS MIGRATION DOES NOT DO
--
-- It does not move the rows already sitting in session_ended_events. No migration in
-- this chain has ever moved data, and a set based copy would have to SELECT from a
-- table that has row-level security FORCED, which applies to the table owner the
-- migration runs as, so the copy would either be refused or silently depend on the
-- deployment's migration role happening to be a superuser. That is a worse property
-- than the one it would fix. session_ended_events is left completely intact and
-- readable, so an old binary mid rolling upgrade keeps working.
--
-- THE OPERATOR OBLIGATION THAT FOLLOWS. The full statement lives in both CHANGELOGs,
-- because a SQL comment is not where an operator plans an upgrade; it is repeated here
-- so the decision and its consequence sit together. A deployment with
-- oidc.backchannel_logout_enabled OFF (the default) loses nothing, because nothing
-- consumes the old table. A deployment with it ON loses every row still
-- delivered_at IS NULL when the last old replica stops, and OutboxRepo::depth() counts
-- only outbox_messages, so that orphaned tail is INVISIBLE to the new metrics surface.
-- A pure rolling upgrade does not satisfy the drain on its own: new replicas already
-- route session ends to outbox_messages while old ones drain the old table, so the old
-- tail only shrinks. Before retiring the LAST old replica, run
--
--     SELECT count(*) FROM session_ended_events WHERE delivered_at IS NULL;
--
-- and require it to reach 0.
--
-- It also adds NO RETENTION. outbox_messages grows monotonically: completed and
-- dead-lettered rows are never removed, no role is granted DELETE, and there is no
-- reaper. That is deliberate for PR 1 (a reaper that deletes queue rows is its own
-- review, and the dead-letter tail is evidence an operator must not lose by accident),
-- and it is a real obligation on any deployment that runs this at volume. Retention is
-- carried in the #104 sequence.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (outbox_messages) ENABLEs and FORCEs row-level security, adds the
-- (tenant, environment) isolation policy, adds the nonempty-scope CHECK, uses
-- COLUMN-scoped grants (never a table-wide UPDATE, the #31 lesson), and is registered in
-- scripts/query-audit.sh. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The generic outbox.
--
-- id is an `obx_` scoped identifier (it embeds its (tenant, environment)). `sequence` is
-- the database-assigned monotonic key that both orders the drain and defines "earlier"
-- for the head-of-group rule. It is assigned at INSERT, which can be BEFORE the
-- enqueuing transaction commits, so under CONCURRENT producers a lower sequence can
-- become visible after a higher one. That is why the drain is at-least-once per ROW rather
-- than a high-water-mark, and it is also the reason the strong form of per aggregate
-- ordering has a PRECONDITION on the producers (two enqueues under one ordering key must
-- not have overlapping transactions). A domain write that holds the aggregate's row lock
-- in the transaction it enqueues from meets it; a scheduled job or a replay does not, and
-- the trait documentation says exactly what such a consumer may still assume.
--
-- consumer is the discriminator: the registered name of the drain that owns this
-- message. One queue, many independent consumers, each claiming only its own rows.
--
-- idempotency_key is the producer's dedup handle, UNIQUE within
-- (tenant, environment, consumer). Enqueuing twice for the same domain fact is a no-op
-- rather than a double delivery, which is what lets a producer retry an enqueue safely.
-- It is deliberately NOT the id: the id is minted from entropy and a producer cannot
-- reconstruct it, whereas the idempotency key is derived from the domain fact.
--
-- ordering_key is the aggregate identity within (tenant, environment, consumer). See the
-- header.
--
-- payload is the message body, opaque to the substrate. Note what genericity COSTS
-- against the typed table it replaces for the session-ended consumer: there is no
-- foreign key from a payload field back to the aggregate it names, so the isolation
-- preserving composite reference 0024 could write (the ended session must exist in the
-- same tenant and environment) has no equivalent here. Scope isolation is unaffected
-- (the row carries its own tenant and environment and the policy below keys on them);
-- what is lost is the structural guarantee that a payload names a live in-scope row.
--
-- attempts, next_attempt_at, claimed_at, last_error, completed_at and dead_lettered_at
-- are the lifecycle, and are the ONLY columns a draining consumer mutates and the ONLY
-- ones it is granted UPDATE on. The message body (consumer, idempotency_key,
-- ordering_key, payload, enqueued_at) is immutable once enqueued.
--
-- Every instant is written from the application clock seam, never the database clock, so
-- a backoff schedule and a lease expiry are deterministic under a manual clock in tests.
CREATE TABLE outbox_messages (
    id               text        PRIMARY KEY,
    tenant_id        text        NOT NULL,
    environment_id   text        NOT NULL,
    -- Database-assigned monotonic drain order, and the "earlier" of the head-of-group
    -- rule (never client-supplied).
    sequence         bigint      GENERATED ALWAYS AS IDENTITY,
    -- The registered consumer name that owns this message.
    consumer         text        NOT NULL,
    -- The producer's dedup handle within (tenant, environment, consumer).
    idempotency_key  text        NOT NULL,
    -- The aggregate identity ordering is preserved within.
    ordering_key     text        NOT NULL,
    -- The message body, opaque to the substrate.
    payload          jsonb       NOT NULL,
    -- The number of delivery attempts so far (the cap dead-letters the row).
    attempts         integer     NOT NULL DEFAULT 0,
    -- The backoff gate: the row is eligible only once now >= next_attempt_at.
    next_attempt_at  timestamptz NOT NULL,
    -- The in-flight visibility lease a claim stamps; NULL until first claimed.
    claimed_at       timestamptz,
    -- The most recent failure reason (a bounded, non-secret label); NULL until a failure.
    last_error       text,
    -- The terminal success marker a consumer sets; NULL until completed.
    completed_at     timestamptz,
    -- The terminal give-up marker set once attempts reaches the cap; NULL until then.
    dead_lettered_at timestamptz,
    -- When the message was enqueued, from the application clock seam.
    enqueued_at      timestamptz NOT NULL,
    CONSTRAINT outbox_messages_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- An empty consumer would be claimable by no registered drain and would sit in the
    -- queue forever; an empty idempotency or ordering key would collapse every message
    -- of a consumer into one dedup slot or one ordering group.
    CONSTRAINT outbox_messages_routing_nonempty
        CHECK (consumer <> '' AND idempotency_key <> '' AND ordering_key <> ''),
    CONSTRAINT outbox_messages_attempts_nonnegative
        CHECK (attempts >= 0),
    -- The two terminal markers are mutually exclusive: a message is completed or
    -- dead-lettered, never both. Without this a row could be reported as delivered and
    -- as given up on at once, and the "not terminal" predicate the claim and the
    -- head-of-group rule share would still be satisfied by neither reading.
    CONSTRAINT outbox_messages_one_terminal_state
        CHECK (completed_at IS NULL OR dead_lettered_at IS NULL),
    -- Enqueue idempotency, made structural: one message per (consumer, domain fact).
    UNIQUE (tenant_id, environment_id, consumer, idempotency_key),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The candidate scan: the not-yet-terminal messages of one consumer in one scope, in
-- drain order. The due gate (next_attempt_at) and the lease gate (claimed_at) filter
-- within it.
CREATE INDEX outbox_messages_pending_idx
    ON outbox_messages (tenant_id, environment_id, consumer, sequence)
    WHERE completed_at IS NULL AND dead_lettered_at IS NULL;
-- The head-of-group test: given a candidate, does its group hold a non-terminal row
-- with a lower sequence? With this index that is one probe of the group's minimum
-- rather than a scan of the group, which is what keeps the ordering guarantee from
-- turning the claim into a quadratic query on a deep backlog.
CREATE INDEX outbox_messages_group_head_idx
    ON outbox_messages (tenant_id, environment_id, consumer, ordering_key, sequence)
    WHERE completed_at IS NULL AND dead_lettered_at IS NULL;

-- The ALL-STATES scope index, and why the two partial indexes above cannot stand in for
-- it. Both of them carry WHERE completed_at IS NULL AND dead_lettered_at IS NULL, so
-- they hold only the live tail, and the reader this index exists for spans every state:
--
--   list() returns a consumer's messages in ANY state, newest first, LIMIT n. It is the
--   operator listing and the dead-letter tail, so the completed and dead-lettered rows
--   are most of what it is for, and it is ORDERED, which is the part no other index here
--   can serve.
--
-- Measured on Postgres 18.4, 205k rows, 100 scopes, one consumer, ~3% live. Without this
-- index, list()'s newest 50 is a Bitmap Heap Scan of the scope's ENTIRE history followed
-- by a top-N heapsort: 2050 rows, 2075 shared buffers, 2.345 ms. With it, an Index Scan
-- Backward: 53 buffers, 0.102 ms. The cost of not having it grows with the scope's whole
-- history, not with the page size, so an operator paging fifty rows out of a tenant with
-- a million messages reads the million.
--
-- What this index is NOT justified by, stated because the obvious argument for it is
-- wrong: depth() and the referential-integrity probe a tenant or environment DELETE runs
-- are ALREADY served, by the implicit index behind the
-- UNIQUE (tenant_id, environment_id, consumer, idempotency_key) constraint, which leads
-- with the same three columns. Measured at the same 205k rows and 100 scopes, both plan
-- as a Bitmap Index Scan on that unique index whether this index exists or not, and the
-- heap work is identical. They degrade to a sequential scan only when ONE scope is a
-- large fraction of the table (measured: at four scopes, a quarter each, all three reads
-- become Parallel Seq Scans), and at that selectivity the planner is right and no index
-- would help. So this is one index for one reader, and that reader is the ordered
-- all-states listing.
--
-- 0024 carried session_ended_events_scope_idx (tenant_id, environment_id) and this is the
-- same shape extended, so the consolidation does not lose an index the table it replaces
-- had. The price is one more index to maintain on the busiest table in the schema, on
-- every insert and every lifecycle update, accepted knowingly.
CREATE INDEX outbox_messages_scope_idx
    ON outbox_messages (tenant_id, environment_id, consumer, sequence);

ALTER TABLE outbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_messages_tenant_isolation ON outbox_messages
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data-plane role ENQUEUEs a message inside the domain transaction that caused it
-- (this is the whole point of a transactional outbox), READs the queue to drain it, and
-- mutates the six lifecycle columns. It is NEVER granted a table-wide UPDATE (the #31
-- lesson): the routing (consumer, idempotency_key, ordering_key) and the payload are
-- immutable once enqueued, so a compromised drain cannot re-target a message at another
-- consumer, rewrite its body, or move it into another ordering group and jump the queue.
--
-- What the six columns DO permit, stated because the CHECK below looks stronger than it
-- is: a drain that holds UPDATE on completed_at can also set it back to NULL, which
-- RESURRECTS a completed message and makes it drain again (measured: one row affected,
-- and the message redrains). outbox_messages_one_terminal_state stops a row being
-- completed AND dead-lettered at once; nothing structural stops it being UN-completed,
-- because the lifecycle columns have to be writable for the lifecycle to work. This is
-- not a widening over 0024, which granted the same shape on delivered_at, and it is the
-- reason terminality is enforced by the repository's inline predicates on every write
-- rather than by the schema alone.
GRANT SELECT, INSERT ON outbox_messages TO ironauth_app;
GRANT UPDATE (attempts, next_attempt_at, claimed_at, last_error, completed_at,
              dead_lettered_at)
    ON outbox_messages TO ironauth_app;

-- The control-plane role can ENQUEUE, for the same reason 0024 gave it INSERT on the
-- session-ended outbox: a management-plane domain write that must emit a message has to
-- write it in ITS OWN transaction or the transactional guarantee is a bypass away. It
-- can also READ, so a management status surface can report queue depth, consumer lag,
-- and the dead-letter tail. That last one is the reader the all-states index above exists
-- for: the dead-lettered rows a status surface reports are precisely the rows both
-- partial indexes exclude, and it reads them newest-first with a limit. It does not
-- drain, so it gets no UPDATE, and it can therefore neither retire another plane's
-- message nor extend a lease.
GRANT SELECT, INSERT ON outbox_messages TO ironauth_control;
