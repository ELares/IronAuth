-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Federation outbound login correlation state (issue #75, PR B).
--
-- The generic OIDC upstream (PR B) redirects the browser to an upstream provider's
-- authorization endpoint and later receives the callback. Between the two legs it must
-- correlate the callback to the request it originated, WITHOUT trusting anything the
-- callback carries beyond the opaque `state`. This migration lands the one short-lived,
-- single-use row that holds that correlation:
--
--   federation_login_states: one row per outbound federated authorize leg. It holds:
--     - a scope-embedded `fls_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not-found under another);
--     - state: the opaque, unguessable value handed to the upstream and echoed back at
--       the callback. The callback consumes the row BY state, SINGLE-USE, which is the
--       CSRF defence: a replayed, forged, or absent state matches no consumable row;
--     - nonce: the OIDC `nonce` bound into the upstream authorize request and checked
--       byte-for-byte against the upstream ID token's `nonce` claim (replay defence);
--     - code_verifier_sealed / code_verifier_dek_version: the PKCE `code_verifier`, a
--       short-lived secret, SEALED under the scope's envelope DEK (issue #48) so it is
--       NOT recoverable from a leaked row; an empty sealed value means no PKCE was used.
--       Sealed inline on the data plane (the app role can seal, exactly as it seals user
--       PII), and opened only at the atomic consume;
--     - connector_id: the `cnr_` connector this leg belongs to, so the callback loads the
--       same connector definition the authorize leg used;
--     - return_to: the pending LOCAL `/authorize?...` resume target, so a successful
--       federated login resumes the local authorization request exactly where it paused;
--     - consumed_at: the single-use marker (NULL until consumed at the callback);
--     - expires_at: the TTL from the application clock seam (never the database clock), so
--       expiry is deterministic under a manual clock in tests. Short-lived and bounded.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant-scoped table ENABLES and
-- FORCES row-level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty-scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per-environment federation outbound-login correlation store (issue #75, PR B).
CREATE TABLE federation_login_states (
    -- The fls_ scoped identifier; embeds its (tenant, environment). The seal AAD binds
    -- to this immutable id, so a sealed verifier lifted to another row fails to open.
    id                         text        PRIMARY KEY,
    tenant_id                  text        NOT NULL,
    environment_id             text        NOT NULL,
    -- The opaque state echoed back at the callback. The single-use consume filters on it,
    -- so a replayed/forged/absent state matches no consumable row (the CSRF defence).
    state                      text        NOT NULL,
    -- The OIDC nonce bound into the upstream authorize request, checked against the
    -- upstream ID token's nonce claim.
    nonce                      text        NOT NULL,
    -- The PKCE code_verifier, SEALED under the scope's DEK (issue #48). Never a plaintext
    -- column; an empty sealed value means no PKCE challenge was sent.
    code_verifier_sealed       bytea       NOT NULL,
    -- The DEK version the code_verifier was sealed under.
    code_verifier_dek_version  integer     NOT NULL,
    -- The connector this outbound leg belongs to (a cnr_ id).
    connector_id               text        NOT NULL,
    -- The pending LOCAL /authorize?... resume target.
    return_to                  text        NOT NULL,
    -- The single-use marker: NULL until the callback consumes the row.
    consumed_at                timestamptz,
    -- The row expiry, from the application clock seam (never the database clock), so it is
    -- deterministic under a manual clock in tests. Short-lived and bounded.
    expires_at                 timestamptz NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT federation_login_states_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The callback consumes BY state within scope, so state is unique per (tenant, environment).
CREATE UNIQUE INDEX federation_login_states_state_idx
    ON federation_login_states (tenant_id, environment_id, state);

ALTER TABLE federation_login_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_login_states FORCE ROW LEVEL SECURITY;
CREATE POLICY federation_login_states_tenant_isolation ON federation_login_states
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT and INSERT to persist the outbound leg, and UPDATE for the atomic single-use
-- consume (SET consumed_at). No DELETE grant: like authorization_codes and
-- pushed_authorization_requests, a consumed or expired row is left in place (short-lived
-- and query-filtered by consumed_at/expires_at), never mutated or removed beyond the
-- consume, so a leaked row cannot be deleted to cover a replay attempt either.
GRANT SELECT, INSERT, UPDATE ON federation_login_states TO ironauth_app;
