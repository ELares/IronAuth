-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- EXPAND: give a token hook a NAME and a POSITION, without moving the identity yet.
-- Issue #114 criterion 5, "explicit ordering of multiple hooks on one event". The identity
-- move is 0168, and the split is the point of this file -- see "Why this is two migrations".
--
-- # What the schema said before, and why it could not be ordered
--
-- 0162 made the primary key `(tenant_id, environment_id, client_id)`: exactly one hook per
-- client, by construction. There was no second hook for an ordering to be an ordering OF, so
-- the criterion could not be met by an admin surface alone -- the table had to grow a dimension
-- first.
--
-- # The dimension is a NAME, and the order is a separate column
--
-- Two columns rather than one, because they answer different questions and an operator changes
-- them at different times. `name` is WHICH hook -- the stable handle an admin route addresses,
-- the thing a rollback rolls back and a version history belongs to. `ordinal` is WHEN it runs
-- relative to its siblings, which an operator reorders without redeploying anything.
--
-- Collapsing them into one column was the obvious cheaper design and it is wrong in a specific
-- way: if position were the identity, reordering would rename, so a version history keyed on
-- the identity would follow the POSITION rather than the code, and rolling back "the second
-- hook" after a reorder would restore a different hook's bytes. Keeping them apart means a
-- reorder touches one integer and nothing else.
--
-- # Why this is two migrations
--
-- Because `Phase::Expand` means "safe for the old binary to ignore", and only half of this
-- change is. Adding columns with defaults is: the previously-deployed writer names no hook, its
-- INSERT takes the defaults, and its `ON CONFLICT (tenant_id, environment_id, client_id)` still
-- resolves against the intact primary key. MOVING that primary key is not: the same statement's
-- conflict target stops naming a unique constraint and the deploy endpoint starts failing.
--
-- An earlier draft did both here and called the result an expand, which was false in exactly
-- the way the phase label exists to prevent. So the identity move is 0168, labelled CONTRACT,
-- with its own account of what it breaks. An operator who runs both at once gets the same end
-- state; an operator rolling binaries gets the choice of running this one first.
--
-- # Backfill, and why the default is not a new row
--
-- Every existing hook becomes `('default', 0)`. That is a rename of the row a client already
-- has rather than an addition beside it, so the count of deployed hooks does not change and
-- neither does what any client is issued. `NOT NULL DEFAULT` on both columns makes the backfill
-- the ALTER itself: an existing row is rewritten in place with the defaults, and there is no
-- window in which a row has no name.
--
-- The DEFAULT stays on `name` afterwards, deliberately, and that is what makes the previously
-- deployed writer keep working across this migration.
--
-- # The ordinal is UNIQUE per client, so the order is total
--
-- Two hooks at the same position have no defined order between them, and a dispatch that
-- chained them would produce a token that depends on which row Postgres returned first. That is
-- the same class as the unordered cascade this repository already fixed with an ORDER BY, and
-- it is cheaper to make unrepresentable: a partial order is not an order, so the database
-- refuses one.
--
-- DEFERRABLE, because a REORDER is a permutation. Swapping two hooks means two UPDATEs, and the
-- intermediate state after the first one has a duplicate ordinal in it. A non-deferrable
-- constraint would make the caller sequence its updates through a free slot -- a dance the
-- application would have to get right every time -- so the check happens at COMMIT instead,
-- where the permutation is complete.

ALTER TABLE token_hooks
    ADD COLUMN name    text    NOT NULL DEFAULT 'default',
    ADD COLUMN ordinal integer NOT NULL DEFAULT 0;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_name_nonempty
        CHECK (name <> '' AND name = btrim(name) AND length(name) <= 64),
    ADD CONSTRAINT token_hooks_ordinal_nonnegative
        CHECK (ordinal >= 0);

-- The identity 0168 will promote, added here so it exists and is proven satisfiable before
-- anything depends on it. Every row is `('default', 0)` at this point, so it holds trivially.
ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_named_identity
        UNIQUE (tenant_id, environment_id, client_id, name);

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_ordinal_unique
        UNIQUE (tenant_id, environment_id, client_id, ordinal)
        DEFERRABLE INITIALLY IMMEDIATE;

-- The version history gains the same dimension, for the reason the name exists at all: a
-- version belongs to a HOOK, not to a client. Without this, two hooks on one client would share
-- one version sequence, and rolling one back would restore the other's bytes.
ALTER TABLE token_hook_versions
    ADD COLUMN name text NOT NULL DEFAULT 'default';

ALTER TABLE token_hook_versions
    ADD CONSTRAINT token_hook_versions_name_nonempty
        CHECK (name <> '' AND name = btrim(name) AND length(name) <= 64);

ALTER TABLE token_hook_versions
    ADD CONSTRAINT token_hook_versions_named_identity
        UNIQUE (tenant_id, environment_id, client_id, name, version);

-- STILL NO SECOND INDEX, and 0165 already argued why: the primary key's own columns with the
-- last one reversed is not a new index, because Postgres scans a btree backwards at the same
-- cost. That argument survives the extra column, and the unique constraint added just above
-- brings its own index, which is the prefix the per-hook retention prune scans. An earlier
-- draft of this migration added a `token_hook_versions_prune_idx` here and justified it as
-- growing "the index it scans"; there is no such index to grow.
