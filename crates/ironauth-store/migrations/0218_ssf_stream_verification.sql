-- Shared Signals: when each stream was last verified (issue #143).
--
-- SSF 1.0 section 7.1.4 lets a receiver ASK the transmitter to send it a verification event, so
-- it can prove the delivery path works end to end without waiting for a real security signal.
-- The request is cheap and the work is not: every call mints a signed SET and either queues a
-- row a poll receiver must collect or an outbox message a worker must POST.
--
-- SO THE SPEC DEFINES A RATE, and this column is what makes it enforceable. Section 7.1.4 lists
-- 429 as the answer to a receiver asking too often and names `min_verification_interval` as the
-- transmitter's advertised floor. Without somewhere to record the last request, that floor could
-- only be advertised, and an authenticated receiver could grow its own push queue without bound:
-- the poll side is capped by `ssf.max_owed_sets_per_stream`, but an outbox message is not.
--
-- ONE COLUMN AND NOT A TABLE. What is needed is the LAST request, not a history: the check is
-- "has one interval passed", and a table of every verification request would be an audit log
-- nobody reads that grows with exactly the traffic this exists to limit. The audit trail for
-- verification is the event the transmitter emits, which is durable on its own.
--
-- NULLABLE, meaning never verified, which is what every existing row is. A NOT NULL column with
-- a `now()` default would have made every stream that already exists look as though it had just
-- been verified, and so refuse the first verification a receiver asks for.
ALTER TABLE ssf_streams
    ADD COLUMN last_verification_at timestamptz;

-- ADDITIVE, and it has to be spelled separately. 0216 granted the data plane
-- `UPDATE (status, status_reason, updated_at)` and its bytes are frozen, so this names the new
-- column on its own; Postgres unions column privileges rather than replacing them.
--
-- The data plane owns the write for the reason it owns the status write: the receiver triggers
-- verification on a request path, so the role that serves requests is the role that stamps it.
GRANT UPDATE (last_verification_at) ON ssf_streams TO ironauth_app;
