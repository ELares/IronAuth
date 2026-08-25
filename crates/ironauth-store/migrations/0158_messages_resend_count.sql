-- `resend_count`, so a re-queued delivery gets an outbox job of its own (issue #111
-- criterion 1: "per-message status and resend are available via API").
--
-- # Why a counter and not a flag
--
-- `enqueue` files the delivery job under `idempotency_key = <message id>` (repository.rs), and
-- the outbox is UNIQUE on (tenant, environment, consumer, idempotency_key). That is exactly
-- right for the original send and it is fatal for a resend: re-filing the same key collapses
-- into the completed original and DOES NOTHING, with no error anywhere. The operator sees a
-- 200, the ledger says pending, and no mail is ever sent. A resend therefore needs a key the
-- original cannot collide with, and it needs one per ATTEMPT, because a resend that fails can
-- be resent again.
--
-- The count is that key's discriminator: attempt N files under `<message id>#N`. It is also
-- the only durable record of how many times an operator re-queued a message, which is the
-- question "why did this person get four copies" reduces to.
--
-- # Why the transition is a compare-and-swap and needs no lock
--
-- Resend moves a terminal row back to `pending` with `WHERE state IN ('failed', 'sending')`.
-- Two operators clicking at once serialise on the row lock; the first moves it and the second
-- affects zero rows and is told the message is not in a resendable state. There is no window
-- where both observe `failed`, because the predicate and the write are one statement. A
-- SELECT-then-UPDATE here would send the same mail twice, which is the failure this whole
-- table exists to avoid.
--
-- # Why `sending` is resendable at all
--
-- 0156 said it: a worker that dies mid-delivery leaves the row `sending`, no other worker will
-- ever pick it up, and "recovering it is a decision a person makes with knowledge of whether
-- the provider accepted, which the database does not have". This is the surface that lets the
-- person make it. Resending a `sending` row CAN double-deliver, and that is the operator's
-- call to make rather than one to foreclose by refusing: refusing leaves the row stuck for
-- good, which is the worse of the two failures and has no recovery at all.
ALTER TABLE messages
    ADD COLUMN resend_count integer NOT NULL DEFAULT 0;

-- Never negative. The column is only ever incremented by one in a single statement, so this
-- can only fire on a write nobody has written yet, which is precisely when a CHECK is cheap.
ALTER TABLE messages
    ADD CONSTRAINT messages_resend_count_not_negative
    CHECK (resend_count >= 0);

-- # The grant, and which plane resends
--
-- `messages` grants the app plane UPDATE on named COLUMNS only (0154), and a column not in
-- that list is not writable however correct the statement is. `resend_count` joins the three
-- already there; without this line every resend fails with a permission error rather than a
-- refusal an operator could act on.
--
-- The CONTROL plane is deliberately not granted UPDATE here, and `messages`'s own test says
-- why: "the control plane holds SELECT only; UPDATE here makes the management surface a
-- mailer". A resend reaches this table through the DATA plane, exactly as the original send
-- did. The management API decides WHETHER to resend and the data plane is what mails, which
-- is the same split every other door already uses; granting the control role UPDATE would
-- collapse it for the sake of one endpoint.
GRANT UPDATE (state, failure_reason, resend_count, updated_at) ON messages TO ironauth_app;
