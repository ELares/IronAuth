-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Give `tenant_quota_limits` the two scope obligations it shipped without.
--
-- Migration 0229 created the table with `ENABLE`/`FORCE ROW LEVEL SECURITY` and a scope policy,
-- and with neither a foreign key onto `environments` nor the nonempty-scope CHECK its 114
-- siblings carry. `absent_scope.rs` asserts the first for every forced-RLS table and has failed
-- on `main` ever since, which is the only reason the gap was found: nothing writes the table, so
-- nothing else noticed.
--
-- # What the missing key actually costs
--
-- The RLS policy compares `tenant_id` and `environment_id` against the two `current_setting`
-- values the scoped transaction binds. That makes a row UNREACHABLE from any other scope -- it
-- does not make the scope EXIST. A write naming a tenant and environment that were never created
-- satisfies the policy (the setting says so) and succeeds, and the row it wrote is then reachable
-- only by repeating that same absent scope: invisible to every scope that does exist, and
-- invisible to a scope listing.
--
-- The consequence is a future one, stated as such. NOTHING READS THIS TABLE YET: `ironauth-quota`
-- depends on `ironauth-env` and `ironauth-config` alone and has no path to the store at all, and
-- `QuotaEnforcer::set_tenant_override` -- the seam that would apply a stored override -- documents
-- the management plane as "wired in M15" and has no non-test caller. An earlier version of this
-- comment said "the limiter reads this table by scope", present tense, which is false. When that
-- wiring lands, an override written under a mistyped environment id would be silently inert while
-- reading back under the same typo as though it were in force. The key is what stops that write.
--
-- # The write is not a rewrite of 0229
--
-- Shipped migrations are frozen -- the ledger checksums each file whole, so editing 0229 would
-- make every deployed environment's chain mismatch. This adds the constraints separately, which
-- is also the honest record: the table shipped without them.
--
-- `NOT VALID` is deliberately NOT used. No release writes this table (see above), so a validating
-- add costs one scan of nothing, and a `NOT VALID` constraint would leave exactly the
-- pre-existing rows this exists to forbid unchecked while reading as though it had checked them.

-- The lock timeout 0150 established for a statement that touches `environments`, and for its
-- reasons: an `ADD CONSTRAINT ... FOREIGN KEY` takes a lock on the PARENT as well as the child,
-- and a migration that queues behind an in-flight reader on a hot table blocks every reader
-- behind it. Bounded, so it fails fast and retries rather than stalling a deployment.
--
-- `set_config(..., true)` rather than `SET LOCAL`, because `SET` takes a literal and not an
-- expression. The knob and its default are 0150's.
DO $$
BEGIN
    PERFORM set_config(
        'lock_timeout',
        coalesce(nullif(current_setting('ironauth.migration_lock_timeout', true), ''), '3s'),
        true
    );
END
$$;

-- THE NAME IS LEFT TO POSTGRES, which is 0150's rule and not a detail.
--
-- The first version of this file spelled the constraint out, reasoning that "a later column
-- reorder cannot silently rename it". That has it exactly backwards, and 0150 says so in as many
-- words: it rejected `RENAME CONSTRAINT` because that "would satisfy the rule while leaving the
-- columns in the order the name now denies, so the schema would agree with the matcher and lie to
-- the reader", and chose to let Postgres derive the name as "the property that keeps the next
-- table honest too".
--
-- The rename IS the alarm. `StoreError` recognizes an absent scope by a name ending in
-- `_tenant_id_fkey` (`SCOPE_FK_SUFFIX`), and `absent_scope.rs` asserts every key onto a scope
-- table is recognizable -- so with a derived name, declaring the columns in the wrong order
-- yields `..._tenant_id_environment_id_fkey`, which fails that assertion and is caught. A pinned
-- name survives the reorder, passes both assertions, and ships a constraint whose name denies its
-- own columns. 118 migration files use the derived form; the pinned one would have been the only
-- hand-asserted scope key in the tree.
ALTER TABLE tenant_quota_limits
    ADD FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id);

-- The nonempty-scope CHECK 0229 also missed, which 114 other migrations carry.
--
-- Largely subsumed by the key above -- an empty id matches no `environments` row -- and added
-- anyway, because "largely" is doing work in that sentence and the cost is one constraint. It
-- states the invariant where a reader of this table looks for it rather than one join away, and
-- it is what the rest of the schema does.
ALTER TABLE tenant_quota_limits
    ADD CONSTRAINT tenant_quota_limits_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> '');
