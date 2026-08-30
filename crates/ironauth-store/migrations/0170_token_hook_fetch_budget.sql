-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- How many outbound requests a token hook may make per invocation. Issue #114 criterion 2,
-- "with the capability granted, exceeding the request budget fails deterministically".
--
-- # Zero is not granted, and that is the default
--
-- The column is the GRANT and the BOUND at once: zero means the hook may not fetch at all, and
-- anything above it is both permission and ceiling. One column rather than a boolean plus a
-- number, because the two can never disagree that way -- a `granted` flag beside a budget of
-- zero, or a budget of five beside `granted = false`, are states somebody would have to decide
-- the meaning of.
--
-- `DEFAULT 0` makes every hook that exists today ungranted without a backfill, which is the
-- deny-by-default this sandbox applies to every other capability.
--
-- # Why the ceiling is in the schema
--
-- A budget is what bounds the only host call a hook makes that can BLOCK. Fuel, the memory cap
-- and the epoch deadline are all measured against a guest that is running, so none of them sees
-- time spent inside a host call: the worst case a hook can hold its worker for is its budget
-- times whatever timeout the transport enforces. Leaving the budget unbounded would leave that
-- product unbounded, and a CHECK is the one place the bound cannot be edited by whoever is
-- deploying the hook.
--
-- SIXTEEN, and the reasoning rather than the number: the use this criterion names is a hook
-- enriching a token from one or two upstreams, and a hook that needs more than a handful is
-- doing work that belongs behind one call to something that already aggregated it. Sixteen is
-- far above any real arrangement and small enough that the worst case stays a few seconds
-- rather than a few minutes.

ALTER TABLE token_hooks
    ADD COLUMN fetch_budget integer NOT NULL DEFAULT 0;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_fetch_budget_bounded
        CHECK (fetch_budget >= 0 AND fetch_budget <= 16);
