-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The blind index that lets an annotated trait value resolve a user (issue #624).
--
-- Traits are stored SEALED: migration 0038 added `traits_sealed`, `traits_dek_version` and
-- `traits_schema_version`, and no plaintext column. That makes user-to-trait reads possible
-- and trait-to-user reads impossible, which is why the recovery and verification halves of
-- issue #53 criterion 2 shipped and the LOGIN half did not. `by_identifier` works because
-- `user_identifiers` carries `blind_index`, a keyed HMAC the lookup compares against an
-- indexed column; this table is the same mechanism for the trait fields a schema annotates
-- as login identifiers.
--
-- ONLY annotated fields. A row here exists for a field the ACTIVE schema declares a login
-- identifier and for no other field. An index over every trait field would be a searchable
-- index over arbitrary sealed PII, which is precisely what sealing exists to prevent, and it
-- would be reachable by anyone who can call the login endpoint.
CREATE TABLE user_trait_login_index (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    -- The top-level trait field name, stored in the clear. A FIELD name is schema, not user
    -- data: it comes from the tenant's own published trait schema and is already readable
    -- through the schema introspection surface, so sealing it would protect nothing while
    -- making the lookup impossible.
    field text NOT NULL,
    -- The keyed HMAC of the normalized value under this scope, hex encoded, exactly as
    -- `user_identifiers.blind_index` is. One-way, so the column carries no recoverable
    -- plaintext, and scope-bound, so the same value in two tenants yields two different tags.
    blind_index text NOT NULL,
    user_id text NOT NULL,
    -- The schema version whose annotations produced this row. A row written under a schema
    -- that no longer annotates `field` is stale rather than wrong, and issue #624's point 3
    -- is that "the annotation changed and the index has not caught up" must never read as
    -- "no such user". Recording the version is what lets a reader tell those apart instead
    -- of guessing from an absent row.
    schema_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, field, blind_index, user_id),
    -- `users.id` is the primary key on its own, so the reference is by id alone, exactly as
    -- `user_identifiers` (0041) and every other user-owned table does it. The scope columns
    -- are still carried and still fenced by the isolation policy below; they are the RLS
    -- key, not part of the foreign key.
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- DELIBERATELY NOT UNIQUE on (tenant_id, environment_id, field, blind_index).
--
-- Uniqueness here would make the second user to hold a value fail to WRITE, which turns an
-- ambiguous login into a failed profile update somewhere else entirely and at a time the
-- operator cannot connect to it. Issue #624 point 4 asks for something different and
-- stronger: two users sharing an annotated value must not resolve to EITHER of them.
--
-- So ambiguity is representable here on purpose, and the LOOKUP refuses when it matches more
-- than one row. `user_identifiers` can afford uniqueness because `UniquenessMode` is a
-- declared policy on that surface; traits carry no such policy, so ambiguity is reachable and
-- the safe answer is to refuse rather than to pick. Picking one arbitrarily would be an
-- account-takeover primitive: plant the value, be chosen, own the account.
CREATE INDEX user_trait_login_index_lookup_idx
    ON user_trait_login_index (tenant_id, environment_id, field, blind_index);

-- The reverse direction, for rewriting a user's rows when their traits change and for
-- dropping them when a field stops being annotated.
CREATE INDEX user_trait_login_index_user_idx
    ON user_trait_login_index (tenant_id, environment_id, user_id);

ALTER TABLE user_trait_login_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_trait_login_index FORCE ROW LEVEL SECURITY;

CREATE POLICY user_trait_login_index_scope_isolation ON user_trait_login_index
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane RESOLVES a login identifier to a user on the authentication path, so it
-- reads. It also WRITES, unlike `api_keys`, because a self-service profile update that
-- changes an annotated trait must update the index in the SAME transaction as the trait: an
-- index the data plane could not maintain would go stale exactly when a user changes the
-- value they are about to log in with, and the next login would refuse them.
GRANT SELECT, INSERT, DELETE ON user_trait_login_index TO ironauth_app;

-- No UPDATE for either plane. A row is (field, blind_index, user_id) and every column of it
-- is part of the identity being indexed, so there is nothing to update: a changed value is a
-- DELETE of the old row and an INSERT of the new one. Granting UPDATE would permit
-- repointing an existing tag at a different user, which is the account-takeover write this
-- table must not allow.
GRANT SELECT, INSERT, DELETE ON user_trait_login_index TO ironauth_control;
