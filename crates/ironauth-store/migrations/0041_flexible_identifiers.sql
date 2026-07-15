-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Flexible identifiers on the central canonicalization seam (issue #54).
--
-- The bootstrap `users` directory carries ONE login handle per user
-- (users.identifier, sealed and blind-indexed by issue #48). Real identity needs
-- MANY typed login identifiers per user (an email, a username, a phone), each with
-- its own verified state, and it needs uniqueness to be a POLICY (environment-wide,
-- org-scoped, or non-unique) rather than a fixed schema constraint. This migration
-- lands the persistent half: one new tenant-scoped `user_identifiers` table.
--
-- The canonicalization seam is the point of the whole feature. Each row stores the
-- CANONICAL form of its identifier as a per-tenant keyed-HMAC BLIND INDEX
-- (`canonical_bidx`), which is what every equality lookup, uniqueness check, and
-- (future) lockout / access decision queries, and stores the RAW input the user
-- typed as AEAD-sealed ciphertext (`raw_sealed`) for display and round-trip. The
-- canonical form itself is derived exactly once, at the application boundary, by
-- the single `ironauth_store::identifier::canonicalize_identifier` seam before it is
-- blind-indexed here; two raw inputs that canonicalize identically (mixed case, a
-- zero-width space, a fullwidth homoglyph) therefore produce the SAME blind index
-- and are one identifier everywhere. The plaintext identifier never lands on a
-- column: a database dump reveals neither the value nor a reversible hash (issue
-- #48).
--
-- Uniqueness as configuration, not code. A single table-wide UNIQUE constraint
-- cannot express three per-environment modes, so uniqueness rides a nullable
-- `uniqueness_key` discriminator computed at write time from the configured mode
-- (`ironauth_config::identifiers.uniqueness`) and enforced by a PARTIAL unique index:
--
--   * environment-wide (the default): key = 'env', a constant, so the index
--     collapses to per-(tenant, environment, type, canonical) uniqueness;
--   * org-scoped: key = 'org:<org-id>' (meaningful once M10 org membership ships),
--     falling back to 'env' for a membership-free user;
--   * non-unique: key = NULL, excluded from the partial index, so duplicates are
--     allowed and identifier-first login still resolves deterministically.
--
-- A creation or update whose canonical form collides within the configured scope is
-- refused by this index as a unique violation, mapped to the deterministic
-- StoreError::Conflict. Changing the mode on a populated environment recomputes the
-- keys (a validation pass reports collisions before the change applies), which is
-- why the key is a normal updatable column rather than a generated one.
--
-- Migration safety obligation (see migrate.rs): the new tenant-scoped table ENABLEs
-- and FORCEs row-level security, adds the (tenant, environment) isolation policy and
-- the nonempty-scope CHECK, is registered in scripts/query-audit.sh, and takes
-- COLUMN-SCOPED grants (never a table-wide UPDATE, the #31 lesson). Every statement
-- is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per-user typed login-identifier set.
--
-- id is a `uid_` scoped identifier (embeds its (tenant, environment)), so a row
-- minted in one scope parses as a uniform not-found under another. user_id is the
-- owning `usr_` user. identifier_type is the closed kind (email, username, phone),
-- which drives the per-type canonicalization policy and is bound into the blind
-- index so the SAME string as an email and as a username never collides. verified
-- is the per-identifier verification flag (M7 owns the ceremonies that flip it).
CREATE TABLE user_identifiers (
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The owning user (the `usr_` subject the tokens are minted for).
    user_id         text        NOT NULL,
    -- The closed identifier kind, pinned by a CHECK; drives canonicalization.
    identifier_type text        NOT NULL,
    -- The blind index of the CANONICAL identifier: a deterministic per-tenant keyed
    -- HMAC over (label, scope, type, canonical value). What every equality lookup
    -- and the partial unique index below query. Never a bare hash of the value.
    canonical_bidx  bytea       NOT NULL,
    -- The RAW input the user typed, sealed under the scope's DEK (issue #48) for
    -- display and round-trip. The plaintext never lands on a column.
    raw_sealed      bytea       NOT NULL,
    -- The DEK version that sealed raw_sealed (for transparent open on read).
    pii_dek_version integer     NOT NULL,
    -- The per-identifier verification flag. False until a verification ceremony
    -- (M7) proves control of the address; an unverified identifier is still a valid
    -- login handle unless a policy (M7) says otherwise.
    verified        boolean     NOT NULL DEFAULT false,
    -- The uniqueness discriminator computed from the configured mode at write time:
    -- 'env' (environment-wide), 'org:<id>' (org-scoped), or NULL (non-unique, exempt
    -- from the partial unique index). Not PII; a plain policy tag.
    uniqueness_key  text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identifiers_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT user_identifiers_type_known
        CHECK (identifier_type IN ('email', 'username', 'phone')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- All of one user's identifiers (the account-management list read).
CREATE INDEX user_identifiers_user_idx
    ON user_identifiers (tenant_id, environment_id, user_id);

-- Identifier-first resolution: given a submitted, canonicalized identifier, find
-- the matching row(s) by (type, canonical blind index) within scope. Non-unique
-- mode can return several, so this is a plain (non-unique) index.
CREATE INDEX user_identifiers_resolve_idx
    ON user_identifiers (tenant_id, environment_id, identifier_type, canonical_bidx);

-- Uniqueness as configuration: a PARTIAL unique index over the mode discriminator.
-- A NULL uniqueness_key (non-unique mode) is excluded, so duplicates are allowed;
-- an 'env' or 'org:<id>' key participates, so a second row with the same
-- (scope, type, canonical, key) is refused as a unique violation. The whole feature
-- rests on canonical_bidx being the CANONICAL form: post-canonicalization collisions
-- are exactly what this rejects.
CREATE UNIQUE INDEX user_identifiers_uniqueness
    ON user_identifiers (tenant_id, environment_id, identifier_type, canonical_bidx, uniqueness_key)
    WHERE uniqueness_key IS NOT NULL;

ALTER TABLE user_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identifiers FORCE ROW LEVEL SECURITY;
CREATE POLICY user_identifiers_tenant_isolation ON user_identifiers
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Both planes add and read a user's identifiers (self-service account management
-- and admin user management), and both may flip the verified flag or recompute the
-- uniqueness_key on a mode-change validation pass. The immutable columns (the
-- identifier value, its type, the owning user) are never updated, so the UPDATE
-- grant is COLUMN-SCOPED to exactly the mutable trio, never a table-wide UPDATE
-- (the #31 lesson).
GRANT SELECT, INSERT ON user_identifiers TO ironauth_app, ironauth_control;
GRANT UPDATE (verified, uniqueness_key, updated_at)
    ON user_identifiers TO ironauth_app, ironauth_control;
