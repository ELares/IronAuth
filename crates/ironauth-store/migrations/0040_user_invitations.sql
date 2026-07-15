-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- User invitation flows (issue #60).
--
-- Inviting a user who does not yet have credentials is a day-one need for every
-- B2B and internal-tools deployment. An admin creates an invitation for a new
-- identity (created in the pending_verification lifecycle state through the #52
-- audited management API), the invitee receives a single-use, expiring,
-- unguessable token, and accepting it sets a credential (a password via the #20
-- Argon2id path, or a passkey deep link) and transitions the user out of
-- pending_verification into active, invalidating the token.
--
-- This migration lands the one new piece of persistent state that flow needs: a
-- tenant-scoped `user_invitations` table. Everything else reuses existing state:
-- the invited user is a normal `users` row (created and activated through the #52
-- repos, which already have the INSERT and column-scoped state/updated_at UPDATE
-- grants from 0037, and the column-scoped password_hash UPDATE from 0036), and
-- the credential is the bootstrap Argon2id verifier from 0020.
--
-- The token is a scope-declaring reference credential of the form
-- `ira_inv_<inv-id>~<256-bit-secret>` (mirroring the #21 refresh token and the
-- #29 opaque access token): ONLY the SHA-256 digest of the whole token is stored,
-- so a database dump yields nothing replayable. Accepting consumes the invitation
-- atomically (a guarded pending -> accepted flip in one transaction), so a token
-- cannot be redeemed twice and a concurrent double-accept redeems at most once.
--
-- The invited identifier (an email or other login handle) is user PII, so it is
-- envelope-encrypted (issue #48): `target_identifier_sealed` is the AEAD-sealed
-- value (for display and re-invite) and `target_identifier_bidx` is the
-- per-tenant keyed blind index (for an equality lookup by identifier, the
-- resend-verification path). The plaintext identifier never lands on a column.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table
-- (user_invitations) ENABLEs and FORCEs row-level security, adds the (tenant,
-- environment) isolation policy, adds the nonempty-scope CHECK, and is registered
-- in scripts/query-audit.sh. Every statement is additive, so this migration is an
-- EXPAND. No `users` grant changes are needed: the invite-create and accept paths
-- reuse the INSERT / column-scoped UPDATE grants 0036 and 0037 already established.

-- ---------------------------------------------------------------------------
-- The per-invitation record (issue #60).
--
-- id is an `inv_` scoped identifier (embeds its (tenant, environment)), so an
-- invitation id minted in one scope parses as a uniform not-found under another;
-- it is also the routing handle embedded in the token wire form. user_id is the
-- `usr_` id of the pending_verification user this invitation provisions (created
-- through the #52 repo at invite time, activated on accept). token_digest is the
-- SHA-256 hex digest of the WHOLE token, the single-use lookup key; the plaintext
-- token is never stored. target_identifier_sealed / target_identifier_bidx are the
-- sealed value and blind index of the invited identifier (user PII, issue #48).
-- credential_type is the closed set of primary-login credentials the accept flow
-- enrolls (a password, or a passkey deep link). state is the closed invitation
-- lifecycle (pending -> accepted, or pending -> revoked). org_context is an opaque
-- org handle M10 layers membership semantics on (carried, not interpreted here).
-- expires_at bounds the token's life (the accept refuses a stale invite). The
-- accepted_at / revoked_at timestamps record the terminal transition.
CREATE TABLE user_invitations (
    id                       text        PRIMARY KEY,
    tenant_id                text        NOT NULL,
    environment_id           text        NOT NULL,
    -- The pending_verification user (a `usr_` id) this invitation activates.
    user_id                  text        NOT NULL,
    -- The SHA-256 hex digest of the WHOLE token; the plaintext token is never
    -- stored, so a database dump yields nothing replayable.
    token_digest             text        NOT NULL,
    -- The invited identifier, sealed under the scope's DEK (issue #48). User PII
    -- never lands on a plaintext column.
    target_identifier_sealed bytea       NOT NULL,
    -- The per-tenant keyed blind index of the invited identifier, for an equality
    -- lookup (the resend-verification path) without a plaintext column.
    target_identifier_bidx   bytea       NOT NULL,
    -- The DEK version the identifier was sealed under (for transparent open).
    pii_dek_version          integer     NOT NULL,
    -- The primary-login credential the invitee enrolls on accept.
    credential_type          text        NOT NULL,
    -- The invitation lifecycle state.
    state                    text        NOT NULL DEFAULT 'pending',
    -- An opaque org handle M10 layers membership on; carried, not interpreted here.
    org_context              text,
    expires_at               timestamptz NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    -- When the invitation was redeemed (present only in the accepted state).
    accepted_at              timestamptz,
    -- When the invitation was revoked (present only in the revoked state).
    revoked_at               timestamptz,
    CONSTRAINT user_invitations_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed credential set: an unknown type can never be written.
    CONSTRAINT user_invitations_credential_type_known
        CHECK (credential_type IN ('password', 'passkey')),
    -- The closed lifecycle: an unknown state can never be written.
    CONSTRAINT user_invitations_state_valid
        CHECK (state IN ('pending', 'accepted', 'revoked')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The digest is the single-use lookup key: at most one invitation per scope may
-- carry a given digest, so a resend (which overwrites the digest with a fresh one)
-- and an accept (which looks a digest up) can never be ambiguous. Scope-keyed, so
-- an unguessable 256-bit-secret token never collides across tenants.
CREATE UNIQUE INDEX user_invitations_digest_unique
    ON user_invitations (tenant_id, environment_id, token_digest);
-- The admin list reads a scope's invitations ordered by (created_at, id).
CREATE INDEX user_invitations_scope_idx
    ON user_invitations (tenant_id, environment_id, created_at, id);
-- The resend-verification path resolves an invitation by the invited identifier's
-- blind index within scope.
CREATE INDEX user_invitations_identifier_idx
    ON user_invitations (tenant_id, environment_id, target_identifier_bidx);

ALTER TABLE user_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY user_invitations_tenant_isolation ON user_invitations
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- ---------------------------------------------------------------------------
-- Grants.
--
-- The control plane creates an invitation (INSERT), lists and inspects it
-- (SELECT), and revokes or resends a PENDING one (a COLUMN-scoped UPDATE of
-- exactly the lifecycle, the rotated digest, the reset expiry, and the timestamps;
-- never a table-wide UPDATE, the #31 lesson). It also seals and blind-indexes the
-- invited identifier through the envelope substrate, so it reads the scope's KEK
-- and DEK exactly as the #52 admin-user path does (0037 already grants that; no
-- repeat is needed here).
GRANT SELECT, INSERT ON user_invitations TO ironauth_control;
GRANT UPDATE (state, token_digest, expires_at, updated_at, accepted_at, revoked_at)
    ON user_invitations TO ironauth_control;

-- The data plane ACCEPTS an invitation: it resolves a presented token to its
-- pending invitation by digest (SELECT) and, in one transaction, flips it to
-- accepted (a COLUMN-scoped UPDATE of exactly the lifecycle and its timestamp) and
-- activates the invited user (the users password_hash / state / updated_at grants
-- from 0036 and 0037). COLUMN-scoped UPDATE only (the #31 lesson): the accept
-- never rewrites the digest, the sealed identifier, or the expiry.
GRANT SELECT ON user_invitations TO ironauth_app;
GRANT UPDATE (state, accepted_at, updated_at) ON user_invitations TO ironauth_app;
