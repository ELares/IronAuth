-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Raise the token-hook component bound from 8 MiB to 16 MiB, issue #114 criterion 1.
--
-- # Why the old bound was wrong, and it was not wrong by a little
--
-- 0162 set 8 MiB on the reasoning that a claim-shaping hook is "under a hundred kilobytes",
-- which is true of a hook compiled from Rust. Criterion 1 also asks for a TypeScript hook, and
-- a hook written in a scripting language carries its interpreter: the sample this repository
-- now ships, `crates/ironauth-hooks/guests-ts`, is a component of roughly 10.6 MiB, of which
-- the author's own code is about four kilobytes.
--
-- So 8 MiB did not merely squeeze TypeScript hooks. It made every one of them undeployable
-- through this product's own admin surface, while the integration suite ran them happily,
-- because the suite loads a component from disk and never crosses this constraint. A sample
-- that cannot be deployed through the API it is a sample for is not a sample.
--
-- # Why 16 MiB, and why it is not configurable
--
-- 16 MiB is the shipped sample's size with roughly 1.5x of headroom, and it is deliberately not
-- an operator setting. A CHECK constraint cannot read configuration, so a tunable cap would
-- mean an application bound and a database bound that are allowed to disagree -- which is the
-- exact failure the comment on `MAX_COMPONENT_BYTES` in `ironauth-admin` already warns about,
-- and which is currently prevented by the two numbers being one number crossed by a test that
-- writes a component of exactly this size through the real handler.
--
-- The reason for a bound at all is unchanged and is in 0162: this column is read on the
-- ISSUANCE path, so an unbounded one is an unbounded read on every login for that client.
-- Doubling it doubles that worst case, which is the cost being accepted here.
--
-- # Dropped and re-added rather than altered, and NOT with the NOT VALID dance
--
-- Postgres has no ALTER CONSTRAINT for a CHECK expression, so the bound has to be dropped and
-- re-added. The obvious next move is ADD ... NOT VALID followed by a separate VALIDATE, so the
-- table scan runs under SHARE UPDATE EXCLUSIVE instead of ACCESS EXCLUSIVE and readers keep
-- going. An earlier version of this migration did exactly that and said so.
--
-- IT BUYS NOTHING HERE, and the reason is in the runner rather than in this file.
-- `MigrationRunner::run_locked` does `let mut tx = self.pool.begin()` and then
-- `sqlx::raw_sql(migration.sql)` -- ONE transaction per FILE (crates/ironauth-store/src/
-- migrate.rs). So the ACCESS EXCLUSIVE lock the DROP takes is held until the file commits,
-- across any VALIDATE that follows it. Splitting the work into two statements changes which
-- lock the second one ASKS for and not which lock is already held, and writing a comment
-- claiming otherwise would be a migration that describes a concurrency property it does not
-- have -- frozen at merge, since the checksum covers the whole file including this text.
--
-- So: a drop and a re-add per table, validated immediately, and the cost stated plainly for
-- BOTH tables -- because this file bounds two of them, and an earlier version of this sentence
-- said "two statements" while describing only the first pair. It was written when the file had
-- one table; `token_hook_versions` was appended below it and the sentence was not revisited.
--
-- `token_hooks` holds at most one row per client that has a hook, so its validating scan is
-- proportional to the number of clients WITH HOOKS rather than to logins or tokens. That is
-- milliseconds on the deployments this ships to.
--
-- `token_hook_versions` is the larger of the two and is worth naming separately: it holds up to
-- TOKEN_HOOK_VERSION_RETENTION rows per client -- twenty -- and its rows are megabytes each.
-- So its scan is up to twenty times the row count of the first, over far more bytes. It is
-- still a scan of one row per historical deploy rather than of anything that grows with
-- traffic, and the prune keeps it bounded, but a deployment with many hooked clients should
-- expect this migration to be the slower of the two ALTERs rather than an instant one.
--
-- Both run under a lock that blocks issuance reads of `token_hooks` for the duration of the
-- whole file. A deployment where that is unacceptable has a problem with the
-- one-transaction-per-file runner, not with this bound, and the fix belongs there.
--
-- No existing row can fail: the old bound was strictly TIGHTER, so everything that satisfied
-- 8388608 satisfies 16777216.

ALTER TABLE token_hooks
    DROP CONSTRAINT token_hooks_component_bounded;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_component_bounded
    CHECK (octet_length(component) > 0 AND octet_length(component) <= 16777216);

-- AND THE HISTORY TABLE, which carries a deliberate copy of the same bound.
--
-- 0165 duplicated it on purpose -- its own comment says "a history row is a candidate for
-- becoming the active row, so anything this table admits that `token_hooks` would refuse is a
-- rollback that fails at the write instead of at the read" -- and the copy is what makes
-- raising one and not the other a real defect: a TypeScript hook would deploy and then fail to
-- be RECORDED, so the write that installed it would roll back.
--
-- This table did not exist when this migration was first written. It arrived from another
-- branch carrying 0162's number, and `every_component_bound_admits_the_shipped_typescript_hook`
-- is what found it: that test evaluates every component bound in the schema against the real
-- artifact rather than naming the tables it knows about, so a table nobody thought to list is
-- exactly the case it exists for.
ALTER TABLE token_hook_versions
    DROP CONSTRAINT token_hook_versions_component_bounded;

ALTER TABLE token_hook_versions
    ADD CONSTRAINT token_hook_versions_component_bounded
    CHECK (octet_length(component) > 0 AND octet_length(component) <= 16777216);
