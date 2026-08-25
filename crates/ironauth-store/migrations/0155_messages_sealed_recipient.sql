-- The sealed recipient on a queued message (issue #111 criterion 1).
--
-- Migration 0154 stored the recipient as a blind index ONLY, and said why: the index answers
-- every question dedup and listing ask, nothing rendered an address back, and "adding it later
-- is a column and an open path, whereas un-shipping a plaintext column is a migration and a
-- disclosure". This is that later, and the caller it was waiting for is the delivery consumer.
--
-- A consumer cannot mail a blind index. To render and send, it has to recover the address, so
-- the address has to survive the enqueue. The choice is where: sealed in this row, or plaintext
-- on the outbox payload every consumer worker reads. This is the first of those.
--
-- Sealed under the scope's active DEK with the same envelope machinery `email_otp_codes` and
-- `magic_link_tokens` use for the same datum (issue #48), under its own AAD label so a seal
-- from one table cannot be opened in the context of another. The blind index STAYS: it is what
-- the collapse and any listing key on, and it works without opening anything.
ALTER TABLE messages ADD COLUMN recipient_sealed bytea;
ALTER TABLE messages ADD COLUMN pii_dek_version integer;

-- Both or neither. A sealed value with no version cannot be opened, and a version with no
-- sealed value is a row that claims a secret it does not hold; either is a delivery that fails
-- at the moment it is attempted rather than at the moment it was written.
ALTER TABLE messages ADD CONSTRAINT messages_sealed_recipient_paired
    CHECK ((recipient_sealed IS NULL) = (pii_dek_version IS NULL));

-- NULLABLE, and that is deliberate rather than lazy. Rows written by 0154 have no sealed
-- recipient and never will: there is no plaintext anywhere to seal, by construction. A
-- backfill is impossible, so the column cannot be NOT NULL without a migration that fails on
-- any deployment that already enqueued. The consumer treats a NULL as an undeliverable message
-- and says so, rather than retrying something that can never succeed.
