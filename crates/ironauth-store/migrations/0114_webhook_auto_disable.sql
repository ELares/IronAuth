-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Automatic endpoint disabling after sustained failure (issue #106).
--
-- A receiver that has been dead for a long time is not usefully retried forever. Every
-- delivery to it costs an outbound request, a retry schedule and a dead letter, and the
-- backlog keeps growing while nobody is listening. Svix sets the reference behaviour here:
-- disable the endpoint, make it obvious, and let the operator turn it back on.
--
-- ## Two columns rather than an audit row
--
-- An automatic disable has no ACTOR. `ActorRef` is Human, Service or Agent, and inventing
-- a fourth for "the delivery worker decided" would change the audit model for every
-- consumer of it, so the fact is recorded on the ROW instead: when it happened and why.
-- The operator decisions in this subsystem (register, rotate, pause, resume, replay) still
-- carry their own audit rows, and they stay attributable because nothing machine-driven is
-- now mixed in among them.
--
-- `disabled_reason` is a bounded internal label, never anything derived from a receiver's
-- response, for the same reason the attempt history stores no response body.
--
-- Both columns are cleared on RESUME, so they describe the CURRENT disabled state rather
-- than accumulating a history. The history of what failed is `webhook_delivery_attempts`,
-- which is the table that exists for it.
ALTER TABLE webhook_endpoints
    ADD COLUMN auto_disabled_at timestamptz,
    ADD COLUMN disabled_reason  text;

-- Set together or not at all: a reason with no instant cannot be shown to an operator in
-- any useful way, and an instant with no reason is the state without the explanation that
-- makes it actionable.
ALTER TABLE webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_auto_disable_complete
    CHECK ((auto_disabled_at IS NULL) = (disabled_reason IS NULL));

-- The control plane's column-scoped UPDATE (0111) is extended to the two new columns, so
-- RESUME can clear them. Without this a resumed endpoint would keep reporting itself
-- auto-disabled forever, which is the same half-set failure 0112 had to avoid.
GRANT UPDATE (auto_disabled_at, disabled_reason)
    ON webhook_endpoints TO ironauth_control;

-- The DATA plane gains its FIRST write on this table, and the narrowness is the argument.
--
-- 0111 gave the deliverer SELECT alone, on the stated ground that it "opens the sealed
-- secret to sign and never mutates a row". Auto-disable is the one thing it must now be
-- able to do, because it is the only part of the system that knows an endpoint has stopped
-- answering; a control-plane process cannot decide this without duplicating the delivery
-- path just to observe it.
--
-- So the grant is exactly the three columns that turn deliveries off and say why. It is
-- NOT the shape 0099's outbox grant was refused for: there is no DELETE here, and no
-- column granted that could destroy or alter evidence. Specifically the deliverer still
-- cannot touch `url` (it cannot redirect a customer's webhooks somewhere else),
-- `secret_sealed` or `secret_dek_version` (it cannot rotate a secret out from under a
-- consumer or replace one with a value it chose), or `description`.
--
-- The worst a compromised deliverer gains is the ability to stop deliveries it was already
-- performing, while leaving a row that says so and a queue that still holds every
-- undelivered message for replay. That is strictly less than it could already do by simply
-- not sending.
GRANT UPDATE (active, auto_disabled_at, disabled_reason, updated_at)
    ON webhook_endpoints TO ironauth_app;
