-- `resend_count`, so a re-queued delivery gets an outbox job of its own (issue #111
-- criterion 1: "per-message status and resend are available via API").
--
-- # Why a counter and not a flag
--
-- `enqueue` files the delivery job under `idempotency_key = <message id>` (repository.rs), and
-- the outbox is UNIQUE on (tenant, environment, consumer, idempotency_key). That is exactly
-- right for the original send and it is fatal for a resend: `enqueue_outbox_in_tx` is the
-- RAISING enqueue, so re-filing the same key raises a unique violation that aborts the whole
-- resend transaction. The row never moves and the operator gets a database error rather than a
-- resend. A resend therefore needs a key the original cannot collide with, and it needs one per
-- ATTEMPT, because a resend that fails can be resent again.
--
-- The silent-collapse reading belongs to `enqueue_outbox_in_tx_ignoring_conflict`, which is a
-- DIFFERENT function that this path does not call. An earlier draft of this migration asserted
-- that mechanism, and review measured it wrong. The conclusion is unchanged and the reason is
-- not, which is worth recording here because this text ships frozen and is what a future reader
-- will reason from.
--
-- The count is that key's discriminator: attempt N files under `<message id>#N`. It is also
-- the only durable record of how many times an operator re-queued a message, which is the
-- question "why did this person get four copies" reduces to.
--
-- THE KEY NOW HAS A GRAMMAR, AND IT HAS A READER. `MessageDeliveryConsumer` recovers the
-- message id from the job's key, and it parsed the WHOLE key as an id, which was true only
-- while the key was the id. `#` is not base64url, so the first version of this change made
-- every resend job fail to parse and be dead-lettered without any provider being reached,
-- leaving the row `pending` where the compare-and-swap below can no longer reach it: strictly
-- worse than the `failed` it started from. `delivery_idempotency_key` and
-- `delivery_key_message_id` are now inverses sitting beside each other for that reason.
--
-- # Why the transition is a compare-and-swap and needs no lock
--
-- Resend moves a terminal row back to `pending` with `WHERE state IN ('failed', 'sending')`.
-- Two operators clicking at once serialise on the row lock: the first moves it, and the second
-- affects zero rows and is told the message is not in a resendable state. There is no window
-- where both observe `failed`, because the predicate and the write are one statement. A
-- SELECT-then-UPDATE here would send the same mail twice, which is the failure this whole
-- table exists to avoid.
--
-- What this does NOT do is bound how often a message may be resent. Resolve-then-resend in a
-- loop is unbounded, and the counter below records it rather than limiting it. The control is
-- the management permission required to call resend at all.
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
