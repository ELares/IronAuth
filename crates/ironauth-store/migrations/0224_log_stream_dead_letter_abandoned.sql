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
    'When the replay found the audit range already deleted by retention, so these events can never be delivered. Mutually exclusive with replayed_at: one means the sink has them, the other means nobody ever will.';

-- OUTSTANDING means neither. An abandoned batch is not awaiting delivery, so it
-- must not block or be retried; it is also not delivered, so it must not be
-- counted as such. The attestation reads it through its own query.
CREATE INDEX log_stream_dead_letters_abandoned_idx
    ON log_stream_dead_letters (tenant_id, environment_id, stream_id)
    WHERE abandoned_at IS NOT NULL;

-- The data-plane role's UPDATE on this table is COLUMN-SCOPED, deliberately: 0140 granted
-- `UPDATE (replayed_at)` and nothing else, so the shipper can clear an entry and cannot
-- rewrite the range, the count, or the error that says what went wrong. A new column is
-- not covered by that grant, and the replay runs as `ironauth_app`, so without this line
-- abandoning a batch is refused by Postgres before any application logic runs and the
-- replay fails with a permission error on a healthy deployment.
--
-- Granted alone rather than widening the grant to the table: the two timestamps are the
-- only columns the data plane has any business writing.
GRANT UPDATE (abandoned_at) ON log_stream_dead_letters TO ironauth_app;
