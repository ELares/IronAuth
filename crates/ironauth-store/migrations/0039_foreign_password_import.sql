-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Streaming bulk import with foreign password-hash support (issue #55).
--
-- A tenant migrating off another identity provider imports its users carrying
-- their EXISTING password hashes from that system (bcrypt, scrypt, PBKDF2, the
-- Argon2 family, or Firebase's modified scrypt). IronAuth stores the foreign hash
-- AS-IS with its algorithm tag and, on the user's NEXT login, verifies against it
-- and transparently rehashes to the native Argon2id verifier (verify-then-rehash),
-- so migration is lossless and the foreign hash is retired on first sign-in.
--
-- This is a purely additive EXPAND on the already-tenant-scoped, forced-row-level
-- security `users` table (issue #20/#52): two new nullable columns and a pair of
-- column-scoped UPDATE grants. No new table, no new policy, no backfill (every
-- existing row keeps both columns NULL, i.e. no foreign credential), so it is safe
-- under a rolling deploy and no prior-release binary reads the new columns.
--
--   1. foreign_password_hash: the imported foreign verifier string in the canonical
--      algorithm-tagged form the ironauth-import scheme layer recognizes. It is a
--      one-way verifier exactly like the native `password_hash` Argon2id column, so
--      it is stored as text, never a plaintext password and never a reversible
--      value (there is no code path that recovers a password from it). NULL for a
--      user with no imported credential.
--
--   2. foreign_password_algo: the non-secret algorithm tag (bcrypt, scrypt, pbkdf2,
--      argon2, firebase-scrypt) the login verify path dispatches on. NULL when
--      there is no foreign hash.
--
-- On the first successful foreign login the data plane writes the fresh Argon2id
-- verifier onto `password_hash` and clears BOTH columns back to NULL in one audited
-- transaction, so the foreign hash exists only until the user signs in once. That
-- clear is the reason the data-plane role (ironauth_app) is granted a COLUMN-SCOPED
-- UPDATE over exactly these two columns (never a table-wide UPDATE, the #31
-- least-privilege lesson); the control plane (ironauth_control) gets the same
-- column-scoped UPDATE so a management-plane re-import or correction can rewrite an
-- imported credential. INSERT of both columns is already covered by the table-wide
-- INSERT grants the import create path uses (ironauth_app from 0006, ironauth_control
-- from 0037).
--
-- Neither column is PII: a password hash is credential material, not a personal
-- identifier, and like the native `password_hash` it is a one-way verifier, so it is
-- outside the pii-encryption taxonomy (scripts/pii-encryption-scan.sh) and stored as
-- text, consistent with how `password_hash` has always been stored.

ALTER TABLE users
    ADD COLUMN foreign_password_hash text,
    ADD COLUMN foreign_password_algo text;

-- The verify-then-rehash landing (data plane) and a management-plane re-import
-- (control plane) both retire or rewrite the foreign hash. A COLUMN-SCOPED UPDATE
-- over exactly the two import columns, never table-wide.
GRANT UPDATE (foreign_password_hash, foreign_password_algo)
    ON users TO ironauth_app, ironauth_control;
