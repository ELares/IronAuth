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
-- # Dropped and re-added rather than altered
--
-- Postgres has no ALTER CONSTRAINT for a CHECK expression. The re-add is NOT VALID plus a
-- separate VALIDATE so the second step takes only SHARE UPDATE EXCLUSIVE: a full-table
-- validation under ACCESS EXCLUSIVE would block issuance reads on this table for its duration,
-- and this table is read on every hooked login. The new bound is strictly weaker than the old
-- one, so no existing row can fail validation.

ALTER TABLE token_hooks
    DROP CONSTRAINT token_hooks_component_bounded;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_component_bounded
    CHECK (octet_length(component) > 0 AND octet_length(component) <= 16777216) NOT VALID;

ALTER TABLE token_hooks
    VALIDATE CONSTRAINT token_hooks_component_bounded;
