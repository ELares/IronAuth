-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-tenant envelope encryption for PII and secrets at rest (issue #48).
--
-- This migration lays the persistence half of the DEK/KEK envelope substrate:
-- three new tenant-scoped tables, isolated exactly like clients and signing_keys
-- (mandatory tenant_id and environment_id, the nonempty-scope CHECK, forced
-- row-level security keyed on the same transaction-local session variables, the
-- same isolation-preserving foreign keys, reached only through the data-plane
-- scoped repository). The cryptography itself is a standard AEAD (ring::aead
-- AES-256-GCM, NIST SP 800-38D) implemented in ironauth-jose; this file stores
-- only wrapped keys and ciphertext, never a plaintext key or a plaintext payload.
--
--   1. tenant_keks: the per-(tenant, environment) key-encryption keys. A KEK is
--      stored ONLY wrapped under the platform master key (wrapped_kek), with the
--      master key id and a version. KEK rotation inserts a higher version and the
--      DEK re-wrap points every DEK at it; CRYPTO-SHREDDING overwrites wrapped_kek
--      with an empty blob and flips status to 'destroyed', after which the scope's
--      DEKs can never be unwrapped again and all of its ciphertext is permanently
--      unreadable. No DELETE grant: destroyed KEK rows are retained as evidence.
--
--   2. tenant_deks: the per-(tenant, environment) data-encryption keys. A DEK is
--      stored ONLY wrapped under the scope's active KEK (wrapped_dek), with the
--      KEK version that wrapped it and a DEK version. New writes seal under the
--      active DEK; older versions stay readable until background re-encryption
--      retires them. KEK rotation UPDATEs wrapped_dek and kek_version in place
--      (a cheap re-wrap, never a payload rewrite).
--
--   3. encrypted_secrets: the transparent encrypted-column store the substrate
--      protects. Each row holds ONLY ciphertext (the secret value sealed under a
--      DEK, with the tenant, environment, and purpose bound as associated data)
--      plus the DEK version that sealed it. There is NO plaintext column. This is
--      where TOTP seeds (M7), connector credentials, and environment-scoped secret
--      values land on encrypted columns from their first write, so no later
--      rewrite migration of a sensitive table is ever needed.
--
-- The substrate half (the three tables above) is expand-only and safe for the old
-- binary: a binary that predates it never reads or writes these tables, and a
-- binary that postdates it provisions a scope's KEK/DEK lazily on first use.
--
-- The substrate is USELESS until the classified PII columns actually route through
-- it, so this migration ALSO applies it to the two plaintext PII columns the
-- bootstrap `users` directory shipped with (issue #48 acceptance: every
-- schema-classified PII column is encrypted, and a database dump yields no
-- plaintext PII). See the `users` PII conversion at the foot of this file. That
-- conversion is a full expand-contract (add sealed columns, drop the plaintext
-- ones) folded into this one migration: `users` is the deliberately-minimal M2
-- bootstrap directory (issue #20), a pre-1.0 slice with no cross-release schema
-- contract and no deployed data to preserve, replaced wholesale in M7, so there is
-- no prior-release binary reading `users.identifier` / `users.claims` to protect
-- across a rolling deploy. When a future encrypted-column conversion targets a
-- table that DOES carry a stability contract or live data, split the contract
-- (the DROP) into a later migration and backfill in between.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy,
-- adds the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. All
-- three do so below. Data-plane writes use COLUMN-SCOPED grants (the #31 lesson:
-- never a table-wide UPDATE that silently covers every future column).

-- ---------------------------------------------------------------------------
-- Per-(tenant, environment) key-encryption keys.
CREATE TABLE tenant_keks (
    -- The kek_ scoped identifier (a public handle; never carries key material).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The KEK version. A rotation inserts a strictly higher version; the active
    -- KEK is the highest version whose status is 'active'.
    version        integer     NOT NULL,
    -- Which platform master key wrapped this KEK (bound into the wrap AAD, so a
    -- KEK wrapped under one master key cannot be unwrapped under another).
    master_key_id  text        NOT NULL,
    -- The KEK material sealed under the master key (nonce || ciphertext || tag).
    -- On a crypto-shred this is overwritten with an empty blob, so the KEK is
    -- unrecoverable and every DEK under it stays permanently wrapped.
    wrapped_kek    bytea       NOT NULL,
    -- 'active' or 'destroyed' (the crypto-shred terminal state).
    status         text        NOT NULL DEFAULT 'active',
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- The crypto-shred instant (from the application clock seam), NULL while live.
    destroyed_at   timestamptz,
    CONSTRAINT tenant_keks_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- One row per (scope, version).
    UNIQUE (tenant_id, environment_id, version),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX tenant_keks_scope_idx ON tenant_keks (tenant_id, environment_id);

ALTER TABLE tenant_keks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_keks_tenant_isolation ON tenant_keks
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to provision and read KEK versions. A COLUMN-SCOPED UPDATE over
-- exactly the three columns rotation and crypto-shredding rewrite: the wrapped
-- KEK bytes, the status, and the destroyed_at instant. Never a table-wide UPDATE
-- (the #31 lesson). No DELETE: destroyed KEK rows are retained as evidence.
GRANT SELECT, INSERT ON tenant_keks TO ironauth_app;
GRANT UPDATE (wrapped_kek, status, destroyed_at) ON tenant_keks TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Per-(tenant, environment) data-encryption keys.
CREATE TABLE tenant_deks (
    -- The dek_ scoped identifier (a public handle; never carries key material).
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The DEK version. New writes seal under the highest 'active' version; older
    -- versions stay 'retired' but readable until background re-encryption.
    version        integer     NOT NULL,
    -- Which KEK version wrapped this DEK. KEK rotation UPDATEs this and the
    -- wrapped bytes in place (a cheap re-wrap, no payload rewrite).
    kek_version    integer     NOT NULL,
    -- The DEK material sealed under the scope's KEK (nonce || ciphertext || tag).
    wrapped_dek    bytea       NOT NULL,
    -- 'active' (the current write version) or 'retired' (readable only).
    status         text        NOT NULL DEFAULT 'active',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_deks_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    UNIQUE (tenant_id, environment_id, version),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX tenant_deks_scope_idx ON tenant_deks (tenant_id, environment_id);

ALTER TABLE tenant_deks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_deks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_deks_tenant_isolation ON tenant_deks
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to provision and read DEK versions. A COLUMN-SCOPED UPDATE over
-- exactly the columns KEK rotation (re-wrap) and DEK rotation (retire) rewrite.
GRANT SELECT, INSERT ON tenant_deks TO ironauth_app;
GRANT UPDATE (wrapped_dek, kek_version, status) ON tenant_deks TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The transparent encrypted-secret store.
CREATE TABLE encrypted_secrets (
    -- The sec_ scoped identifier.
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The purpose / column label, bound into the seal AAD so a ciphertext cannot
    -- be replayed into a different field. Unique per scope, so a purpose names at
    -- most one secret value in a (tenant, environment).
    purpose        text        NOT NULL,
    -- Which DEK version sealed the ciphertext. Bound into the AAD and used to pick
    -- the right DEK on read; background re-encryption advances it to the active DEK.
    dek_version    integer     NOT NULL,
    -- The secret value sealed under the DEK (nonce || ciphertext || tag). This is
    -- the ONLY payload column, and it is never plaintext.
    ciphertext     bytea       NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- The last-write / re-encryption instant (from the application clock seam).
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT encrypted_secrets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    UNIQUE (tenant_id, environment_id, purpose),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX encrypted_secrets_scope_idx ON encrypted_secrets (tenant_id, environment_id);

ALTER TABLE encrypted_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY encrypted_secrets_tenant_isolation ON encrypted_secrets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to write and read secrets; a COLUMN-SCOPED UPDATE over exactly
-- the ciphertext, its DEK version, and the update instant (an upsert overwrite
-- and the background re-encryption path both rewrite these three columns).
GRANT SELECT, INSERT ON encrypted_secrets TO ironauth_app;
GRANT UPDATE (ciphertext, dek_version, updated_at) ON encrypted_secrets TO ironauth_app;

-- ---------------------------------------------------------------------------
-- Route the bootstrap `users` PII columns through the envelope substrate above.
--
-- `users` shipped two plaintext PII columns: `identifier` (the login handle, an
-- email or username) and `claims` (a JSON object of OIDC standard-claim VALUES,
-- for example {"email":"a@b.test","name":"Ada"}). Both are pure PII and must not
-- appear in a database dump, so this converts them to sealed envelope ciphertext.
--
--   * claims is a pure payload (never a lookup key), so it is simply sealed:
--     claims_sealed holds the JSON document sealed under the scope's active DEK,
--     decrypted transparently on read by the OIDC UserInfo path.
--
--   * identifier is a LOOKUP column: login resolves a user BY identifier. AEAD
--     ciphertext is not equality-searchable (a fresh nonce per seal makes every
--     ciphertext of the same value distinct), so the encrypted value cannot be
--     queried directly. The standard pattern is a BLIND INDEX: identifier_bidx
--     stores a deterministic per-tenant keyed HMAC of the identifier (the key is
--     derived from the envelope master key, NOT a bare unsalted hash), which is
--     what equality lookups query, while identifier_sealed holds the AEAD-sealed
--     identifier for display and round-trip. The plaintext identifier never lands
--     in a column, so a dump reveals neither the handle nor a reversible hash.
--
-- pii_dek_version records which DEK version sealed a row's identifier_sealed and
-- claims_sealed, so the read path unwraps the exact DEK that sealed them (older
-- DEK versions stay readable; `users` has no update path, so a row keeps its
-- sealing version for life). The bytea PII columns are added NOT NULL (the
-- application always supplies them on INSERT); `users` is empty at migration time
-- (the whole chain applies before any row is written), so the NOT NULL add needs
-- no backfill default.
ALTER TABLE users
    ADD COLUMN identifier_bidx   bytea,
    ADD COLUMN identifier_sealed bytea,
    ADD COLUMN claims_sealed     bytea,
    ADD COLUMN pii_dek_version   integer;

-- Drop the plaintext PII columns (the contract). Dropping `identifier` also drops
-- the UNIQUE (tenant_id, environment_id, identifier) constraint that depended on
-- it; the equivalent per-scope uniqueness moves onto the blind index below, so a
-- duplicate login handle still fails as a unique violation.
ALTER TABLE users
    DROP COLUMN identifier,
    DROP COLUMN claims;

-- The sealed PII columns are mandatory on every row the application writes.
ALTER TABLE users
    ALTER COLUMN identifier_bidx   SET NOT NULL,
    ALTER COLUMN identifier_sealed SET NOT NULL,
    ALTER COLUMN claims_sealed     SET NOT NULL,
    ALTER COLUMN pii_dek_version   SET NOT NULL;

-- One account per login handle per scope, now enforced on the deterministic blind
-- index: registration relies on this to reject a duplicate identifier as a unique
-- violation, exactly as the plaintext UNIQUE did.
ALTER TABLE users
    ADD CONSTRAINT users_identifier_bidx_unique
        UNIQUE (tenant_id, environment_id, identifier_bidx);

-- No grant change: `users` already GRANTs SELECT, INSERT to ironauth_app (issue
-- #20), which covers the new columns; there is still no UPDATE or DELETE path (the
-- full account lifecycle is M7), so no column-scoped UPDATE grant is added.
