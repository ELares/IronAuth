-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- CONTRACT: move the token-hook identity from (scope, client) to (scope, client, NAME), so a
-- client can hold more than one hook. Issue #114 criterion 5. 0167 added the columns and the
-- new unique constraints; this drops the old identity that forbids the second row.
--
-- # This one is NOT safe for the previously deployed binary, and that is the whole reason it is
-- # a separate file
--
-- The deploy path writes `INSERT INTO token_hooks ... ON CONFLICT (tenant_id, environment_id,
-- client_id) DO UPDATE`. A conflict target must name a unique constraint, and after this
-- migration those three columns are no longer unique on their own. A binary built before this
-- change therefore FAILS on that statement -- measured, not predicted: applying the identity
-- move without updating the writer turned every deploy into a 500.
--
-- What does NOT break, which is most of it:
--
--   * ISSUANCE. The read is `SELECT ... WHERE tenant_id = $1 AND environment_id = $2 AND
--     client_id = $3`, which has no conflict target and keeps working. No login is affected by
--     this migration in either direction, and no old binary can be handed a second hook to be
--     confused by, because only new code can create one.
--   * EVERY DEPLOYMENT WITH THE FEATURE OFF. `wasm-hooks` is experimental and off by default,
--     and its own registration says a deployment that has not enabled it "never reads
--     `token_hooks`". For those installs this migration changes a constraint on a table nothing
--     touches.
--
-- So the exposure is precisely: an install that has ENABLED an experimental feature, is
-- MID-ROLLING-UPGRADE, and DEPLOYS A HOOK during the window. That is the trade the maturity
-- ladder exists to price -- the flag's own text says the interface may still move and an
-- operator enabling it acknowledges which revision they built against -- and an operator who
-- wants none of it can apply 0167 in one release and this in the next, which is what splitting
-- them buys.
--
-- # Why the version history moves too
--
-- A version belongs to a HOOK. Leaving `token_hook_versions` keyed on (scope, client, version)
-- would give two hooks on one client a single shared version sequence, so deploying hook B
-- would advance hook A's numbering and rolling A back would restore B's bytes. The unique
-- constraint 0167 added is promoted for the same reason the active table's is.

ALTER TABLE token_hooks
    DROP CONSTRAINT token_hooks_pkey;

-- DROP THE UNIQUE AND ADD THE PRIMARY KEY IN ONE STATEMENT, so the table never carries two
-- indexes over the identical column list. Adding the primary key while 0167's unique constraint
-- still stood would leave both, and both would be maintained on every deploy of every hook.
--
-- Not `ADD PRIMARY KEY ... USING INDEX`, which is the other way to avoid that and does not
-- apply here: that form adopts an existing index, and this index is OWNED by the unique
-- constraint, so dropping the constraint takes the index with it. An earlier version of this
-- comment claimed `USING INDEX` was what this statement does. It is not, and the difference
-- matters to anyone reading it to learn the pattern.
ALTER TABLE token_hooks
    DROP CONSTRAINT token_hooks_named_identity,
    ADD PRIMARY KEY (tenant_id, environment_id, client_id, name);

ALTER TABLE token_hook_versions
    DROP CONSTRAINT token_hook_versions_pkey;

ALTER TABLE token_hook_versions
    DROP CONSTRAINT token_hook_versions_named_identity,
    ADD PRIMARY KEY (tenant_id, environment_id, client_id, name, version);
