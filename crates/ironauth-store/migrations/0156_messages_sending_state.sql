-- The `sending` state, so two workers cannot both mail one message (issue #111 criterion 1).
--
-- The delivery consumer used to read the row, see `pending`, deliver, then resolve. That is a
-- read-then-act, and the window between the two is real: the outbox leases a job, but a lease
-- can LAPSE (a worker that stalls past its visibility timeout has its job re-claimed while it
-- is still running), and then two workers both observe `pending` and both hand the message to
-- a provider. At-least-once delivery of the JOB is the substrate's contract and is correct;
-- at-least-once delivery of the MAIL is a person receiving the same code twice.
--
-- So the transition out of `pending` becomes the claim. A worker moves `pending` -> `sending`
-- with a conditional UPDATE and delivers only if it moved it; the loser sees zero rows
-- affected and stops. Postgres serialises the two updates on the row lock, so exactly one wins.
--
-- WHAT A CRASH LEAVES. A worker that dies mid-delivery leaves the row `sending`, and no other
-- worker will pick it up, which is deliberate: the alternative is a timeout that lets a second
-- worker mail a recipient the first may already have mailed. A stuck `sending` row is visible
-- to an operator and is the safe direction to fail; recovering it is a decision a person makes
-- with knowledge of whether the provider accepted, which the database does not have.
ALTER TABLE messages DROP CONSTRAINT messages_state_known;
ALTER TABLE messages ADD CONSTRAINT messages_state_known
    CHECK (state IN ('pending', 'sending', 'sent', 'failed'));

-- The pairing rule is unchanged in meaning: a reason belongs to a failure and nothing else.
-- Restated here only because `sending` joins the set it quantifies over.
