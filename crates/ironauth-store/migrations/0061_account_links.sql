-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Guarded account linking: the account_links table (issue #78, PR 1).
--
-- A local user may deliberately bind one or more federated identities (Google,
-- Apple, an enterprise OIDC upstream) to their single local account. Today (issue
-- #77) every federated identity provisions its OWN separate users row and there is
-- no path that attaches a federated (issuer, sub) to a pre-existing local user. This
-- migration lands the one new table that the guarded linking subsystem reads and
-- writes: one row per (local user) to (federated identity) binding.
--
--   account_links: the local-user to federated-identity binding.
--     - a scope embedded `alk_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - user_id: the LOCAL users row this federated identity is linked TO. A single
--       user may hold several links (Google AND Apple AND an enterprise upstream), so
--       the binding is one to many on the user;
--     - connector_id: the `cnr_` connector describing which upstream this identity
--       came through;
--     - external_id_bidx: the keyed BLIND INDEX of the federated composite
--       federated_external_id(issuer, sub), the same blind index primitive the users
--       row uses for its own external_id. The raw federated identifier NEVER lands on
--       a queryable column; only its per tenant keyed HMAC tag does, so an index
--       collision can neither leak nor link across tenants;
--     - external_id_sealed / external_id_dek_version: the raw federated composite
--       sealed under the scope DEK (issue #48) for display and audit only. A database
--       dump carries only ciphertext;
--     - email_verified: the link's OWN immutable trust SNAPSHOT captured at link time.
--       It is a property OF THE LINK (was this binding made under verified to verified
--       conditions), NEVER a promotion of the local identity's verification state: the
--       server owned user_identifiers.verified column (issue #54) is the only place a
--       local identity's verified flag lives, and linking never writes it. The snapshot
--       is IMMUTABLE: the column gets NO GRANT UPDATE at all, so a change of trust means
--       unlink plus relink through a fresh flow, mirroring the immutability discipline
--       of webauthn_user_handle (issue #66);
--     - link_method: how the binding was made, the closed set {manual, auto_verified}
--       enforced by a CHECK so an unknown method can never be written;
--     - created_at: the creation instant (the database clock DEFAULT, a non secret
--       audit timestamp, matching federation_login_states).
--
--     Classified ResourceType::Runtime (issue #41): a link is dynamic per environment
--     end user identity state (like a session, a credential, or a user_identifier),
--     NEVER promotable config, so it STRUCTURALLY never enters a config snapshot (only
--     Promotable types are exported).
--
-- The UNIQUE (tenant, environment, connector, external_id_bidx) constraint is the
-- STRUCTURAL anti takeover invariant: a given federated identity resolves to AT MOST
-- one local user in a scope, so two different local users can never both claim the same
-- (connector, issuer, sub). The last usable method guard (repository.rs) runs the
-- unlink DELETE in the same transaction as its cross source method count, so a DELETE
-- can never strand an account with no usable authentication method.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant scoped table ENABLES
-- and FORCES row level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The local-user to federated-identity binding (issue #78, PR 1).
CREATE TABLE account_links (
    -- The alk_ scoped identifier; embeds its (tenant, environment).
    id                      text        PRIMARY KEY,
    tenant_id               text        NOT NULL,
    environment_id          text        NOT NULL,
    -- The LOCAL user this federated identity is linked to (a `usr_` id). Every read and
    -- the last method count filters on it.
    user_id                 text        NOT NULL,
    -- The connector describing the upstream (a `cnr_` id).
    connector_id            text        NOT NULL,
    -- The keyed blind index of federated_external_id(issuer, sub): an equality lookup
    -- and the per scope anti takeover unique constraint query. Never a plaintext value.
    external_id_bidx        bytea       NOT NULL,
    -- The raw federated composite sealed under the scope DEK (issue #48), for display
    -- and audit only. Only ciphertext ever lands here.
    external_id_sealed      bytea       NOT NULL,
    -- The DEK version that sealed external_id_sealed (for transparent open on read).
    external_id_dek_version integer     NOT NULL,
    -- The link's OWN immutable trust snapshot at link time (see the header note). It
    -- gets NO GRANT UPDATE: a link's trust snapshot is immutable.
    email_verified          boolean     NOT NULL DEFAULT false,
    -- How the binding was made, the closed set {manual, auto_verified}.
    link_method             text        NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_links_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT account_links_link_method_known
        CHECK (link_method IN ('manual', 'auto_verified')),
    -- The STRUCTURAL anti takeover invariant: a federated identity resolves to AT MOST
    -- one local user in a scope.
    CONSTRAINT account_links_identity_uniq
        UNIQUE (tenant_id, environment_id, connector_id, external_id_bidx),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Enumerate a user's linked identities (the self service list read and the last method
-- count).
CREATE INDEX account_links_user_idx
    ON account_links (tenant_id, environment_id, user_id);

ALTER TABLE account_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_links FORCE ROW LEVEL SECURITY;
CREATE POLICY account_links_tenant_isolation ON account_links
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane creates a link (a deliberate, guarded federated login binding), reads
-- a user's links, and DELETEs one on unlink (the last usable method guard runs in the
-- same transaction, so a DELETE can never strand). DELETE is required because a link is
-- genuinely removable, unlike the append only correlation tables. The email_verified
-- trust snapshot gets NO GRANT UPDATE at all: it is immutable for the life of the link.
GRANT SELECT, INSERT, DELETE ON account_links TO ironauth_app;
