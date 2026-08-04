-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Bound `idempotency_keys`, which has grown without limit since 0003 (issue #186).
--
-- The table is the Idempotency-Key replay store. 0003 gave it only `created_at`: no
-- expiry, no reaper, and no DELETE grant to any role, so every management write that
-- carried an Idempotency-Key left a row behind forever. It is the last replay-style
-- table in the schema with no pruning at all; the other four (`client_assertion_jtis`,
-- `external_assertion_jtis`, `dpop_proof_replay`, `pow_challenges`) each prune their
-- own rows already, and this brings the family in line.
--
-- WHY THE COLUMN CARRIES A DEFAULT, which is the load-bearing detail here.
--
-- `insert_idempotency` is reached from 41 call sites and does not take the clock seam.
-- A DEFAULT means the column needs no argument from any of them, and it also makes the
-- change safe under a rolling upgrade (issue #392): an OLD binary's INSERT does not
-- name `expires_at` and still produces a valid row, so both versions can write to this
-- table at once. Adding the column NOT NULL without a default would have failed every
-- write from a node that had not yet been upgraded.
--
-- Twenty four hours is the window. It is the de-facto norm for an idempotency replay
-- cache, and the consequence of a row expiring is that a retry under the same key
-- RE-EXECUTES rather than replaying, which is the documented contract for a key older
-- than the window rather than a failure.
--
-- The DELETE grant goes to `ironauth_control` and to no one else. The data-plane role
-- has no grant of any kind on this table (0003), and the #31 lesson says a standing
-- capability with no caller does not get one.

ALTER TABLE idempotency_keys
    ADD COLUMN expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours';

-- The prune reads this index and nothing else, so it stays bounded as the table grows.
CREATE INDEX idempotency_keys_expires_at_idx ON idempotency_keys (expires_at);

GRANT DELETE ON idempotency_keys TO ironauth_control;
