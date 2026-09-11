-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Distinguish an ABANDONED dead letter from a replayed one (issue #145 criterion 3).
--
-- `replay_dead_letters` re-reads each dead-lettered range out of `audit_log`.
-- When audit retention has already deleted that range there is nothing left to
-- send, and the replay marked the row `replayed_at` anyway, on the reasoning
-- that an entry which can never clear is worse than one marked done.
--
-- That reasoning is right about the queue and wrong about the record. Those
-- events were never delivered and now cannot be: they are gone from the audit
-- log and gone from the sink. Recording that as a replay makes the two
-- outcomes -- "the SIEM has them now" and "nobody will ever have them" --
-- indistinguishable in the only row that remembers either.
--
-- The delivery attestation (`GET .../log-streams/{id}/attestation`) is what
-- made this matter. It answers an auditor asking whether any of the audit
-- trail went missing, and a permanently lost batch is the strongest possible
-- yes. Reading it off `replayed_at` it would have answered no.
--
-- NULLABLE and defaulted to NULL, so every existing row keeps its meaning: a
-- row already marked replayed stays replayed. This does not retro-classify the
-- batches abandoned before this column existed, and nothing can: the evidence
-- that would separate them was never written down.

ALTER TABLE log_stream_dead_letters
    ADD COLUMN abandoned_at timestamptz;

COMMENT ON COLUMN log_stream_dead_letters.abandoned_at IS
    'When the replay found NOTHING left of the audit range, so not one of these events can ever be delivered. Mutually exclusive with replayed_at, and the CHECK below enforces that rather than trusting this sentence.';

-- PARTIAL LOSS IS THE COMMON SHAPE, and the column above cannot express it.
--
-- An age-based retention cutoff lands INSIDE a dead-lettered range as soon as the stream
-- has been broken longer than the distance between the cutoff and the head of its
-- backlog. The replay then assembles the survivors, ships them, and the batch is a
-- successful replay by every test the row can apply -- while the events retention took
-- are gone from the log and were never delivered. Recording only the all-or-nothing case
-- would have left exactly the collapse this migration exists to prevent, for the case
-- that actually happens.
--
-- So the count is stored rather than derived. `event_count` is how many events the failed
-- pass had in hand; this is how many of them no replay will ever recover. Zero on every
-- existing row and on every clean replay, which is the truth for both.
ALTER TABLE log_stream_dead_letters
    ADD COLUMN lost_event_count integer NOT NULL DEFAULT 0;

COMMENT ON COLUMN log_stream_dead_letters.lost_event_count IS
    'How many of this batch''s events audit retention removed before the replay reached them. Nonzero means they were never delivered and cannot be, whether or not the survivors were.';

-- ENFORCED, not asserted. The comment above used to be the only thing saying these two are
-- exclusive, and a row carrying both would be counted as delivered by one query and as
-- permanently lost by the other.
ALTER TABLE log_stream_dead_letters
    ADD CONSTRAINT log_stream_dead_letters_terminal_state_is_one
    CHECK (replayed_at IS NULL OR abandoned_at IS NULL);

-- A batch cannot lose more events than it ever held, and an ABANDONED batch lost all of
-- them: that is what abandonment means, so the two columns cannot drift apart.
ALTER TABLE log_stream_dead_letters
    ADD CONSTRAINT log_stream_dead_letters_lost_within_batch
    CHECK (
        lost_event_count >= 0
        AND lost_event_count <= event_count
        AND (abandoned_at IS NULL OR lost_event_count = event_count)
    );

-- OUTSTANDING means neither replayed nor abandoned. An abandoned batch is not awaiting
-- delivery, so it must not block or be retried; it is also not delivered, so it must not
-- be counted as such. The attestation reads the lost ones through their own query, which
-- keys on the COUNT rather than on `abandoned_at`, because a partially lost batch is a
-- replayed row.
CREATE INDEX log_stream_dead_letters_lost_idx
    ON log_stream_dead_letters (tenant_id, environment_id, stream_id)
    WHERE lost_event_count > 0;

-- The data-plane role's UPDATE on this table is COLUMN-SCOPED, deliberately: 0140 granted
-- `UPDATE (replayed_at)` and nothing else, so the shipper can clear an entry and cannot
-- rewrite the range, the count, or the error that says what went wrong. A new column is
-- not covered by that grant, and the replay runs as `ironauth_app`, so without this line
-- abandoning a batch is refused by Postgres before any application logic runs and the
-- replay fails with a permission error on a healthy deployment.
--
-- Granted alone rather than widening the grant to the table: the two timestamps are the
-- only columns the data plane has any business writing.
GRANT UPDATE (abandoned_at, lost_event_count) ON log_stream_dead_letters TO ironauth_app;
