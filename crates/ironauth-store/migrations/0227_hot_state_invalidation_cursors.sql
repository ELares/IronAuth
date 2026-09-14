-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Where each node has read up to in the invalidation feed (issue #147).
--
-- # Why a cursor and not a queue
--
-- The outbox is a QUEUE: `claim`/`complete` hands each message to exactly one worker, which is
-- right for work that must happen once (deliver a webhook, push an SSF set). Invalidation is the
-- opposite shape. EVERY node must see EVERY invalidation, because every node has its own
-- accelerator holding its own copy, so a message consumed by one node and completed is an
-- invalidation the other nodes never hear about and a cache line that stays wrong for its whole
-- TTL.
--
-- So invalidations are READ rather than claimed: the rows live in `outbox_messages` like every
-- other feed row, and each node keeps its own position here. Two nodes reading the same feed
-- from different positions both see every row, which is broadcast by construction rather than by
-- fan-out.
--
-- # Why there is no ordering lock on the producer, unlike the event feed
--
-- `outbox_messages` carries a per-scope advisory lock for `webhook.event` rows so that sequence
-- order equals COMMIT order (issue #107 criterion 2, #1009). Invalidations deliberately do NOT
-- take it, and the reason is a property of what an invalidation says rather than a shortcut.
--
-- "FORGET KEY K" IS IDEMPOTENT AND ORDER-INDEPENDENT. Applying two invalidations in either
-- order, or the same one twice, leaves the same state: the key is not cached. There is no
-- interleaving of deletes that produces a wrong cache, so the ordering guarantee costs
-- contention and buys nothing here.
--
-- What invalidation DOES need is that it is not applied before the mutation it accompanies is
-- visible, which is what the reader's `xmin < pg_snapshot_xmin(pg_current_snapshot())` watermark
-- gives.
--
-- # AN INVALIDATION CAN STILL BE MISSED, and this comment said otherwise
--
-- The first version of this paragraph claimed a durable per-node cursor makes an invalidation
-- impossible to miss. IT DOES NOT, and `events_after`'s own documentation says so, measured:
-- the watermark is a FILTER and not a prefix cut, so it "serves settled rows that sit ABOVE an
-- unsettled one, so a cursor can advance past a row that is later filled in and a consumer
-- never sees it ... The skip is real, PREDATES this change, and belongs to criterion 1."
--
-- The inversion is reachable here by construction rather than by bad luck. A producer's `xmin`
-- is fixed at its transaction's FIRST write, and this producer is called INSIDE a caller's
-- mutation transaction, after that transaction's own writes -- so a long mutation can hold a
-- low xid while inserting a high sequence, and a short one that started later can hold a high
-- xid on a low sequence. A reader then serves the high sequence, checkpoints past the low one,
-- and the low one is settled beneath every cursor for ever. The append lock would not rescue
-- it either, for the reason that doc gives: the lock orders INSERTs while `xmin` is fixed
-- earlier, so two producers can take it in one order and still have inverted xmins.
--
-- WHAT THE CURSOR ACTUALLY GIVES is the two things it does give, and they are why it is still
-- the right shape: DURABILITY across a restart, and BROADCAST, because no other node can
-- consume a row away from this one.
--
-- WHAT BOUNDS THE MISS is the entry's TTL. An invalidation that is skipped leaves a node
-- serving a stale value until the entry lapses, which for an accelerator use is the ordinary
-- cost of caching and is why `ironauth_hot` caps every accelerator write at ten seconds. So the
-- propagation SLO #147 asks for is not the feed's latency alone: it is the LONGER of that and
-- the cache TTL, and a use whose staleness cannot be bounded by its TTL is a use that should
-- not be read through a cache at all.
--
-- Not taking the lock also avoids inheriting a known deadlock: #1009 records that the advisory
-- lock cannot be made safe from the data plane, because the insert's referential-integrity check
-- takes `FOR KEY SHARE` on `tenants` and `environments` while the lock is held, and those tables
-- are granted to `ironauth_control` alone so the data plane cannot pre-lock them.

CREATE TABLE hot_state_invalidation_cursors (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- WHICH NODE. An operator-supplied identity, stable across a restart of the same node and
    -- distinct between nodes. A node that changes its identity reads the feed from the
    -- beginning, which is safe (a re-applied invalidation deletes an entry that is already
    -- gone) and wasteful, so it is worth getting right.
    node_id        text        NOT NULL,
    -- The sequence this node has applied THROUGH. The next read asks for rows after it.
    applied_through bigint     NOT NULL,
    -- For an operator answering "is a node keeping up", and for the staleness bound: a cursor
    -- whose `updated_at` is far behind now is a node that is not applying invalidations, which
    -- is exactly the condition #147's SLO is about.
    updated_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, environment_id, node_id),

    CONSTRAINT hot_state_invalidation_cursors_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT hot_state_invalidation_cursors_node_bounded
        CHECK (node_id <> '' AND octet_length(node_id) <= 128),
    -- A cursor is a position in a sequence that starts at 1, so zero means "before the first
    -- row" and negative means a bug. Refusing it here stops a node that computed one from
    -- silently re-reading the whole feed for ever.
    CONSTRAINT hot_state_invalidation_cursors_position_sane
        CHECK (applied_through >= 0),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE hot_state_invalidation_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE hot_state_invalidation_cursors FORCE ROW LEVEL SECURITY;

CREATE POLICY hot_state_invalidation_cursors_scope ON hot_state_invalidation_cursors
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT, INSERT and UPDATE. No DELETE: a cursor row is small, one per node per environment, and
-- removing one silently resets that node to the beginning of the feed. If node retirement ever
-- needs to reclaim them, the grant arrives with the retention rule that says when a node counts
-- as gone.
GRANT SELECT, INSERT, UPDATE ON hot_state_invalidation_cursors TO ironauth_app;
