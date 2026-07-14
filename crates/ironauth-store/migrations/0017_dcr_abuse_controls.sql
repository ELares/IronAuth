-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Dynamic Client Registration abuse controls (issue #31).
--
-- Issue #30 shipped the RFC 7591 / 7592 endpoint behind a plain default-off
-- enable flag. This migration lands the abuse-control substrate that WRAPS it:
--
--   1. dcr_policies: named, reusable policy objects, each an ordered list of
--      primitives (force / restrict / reject / default) over registration
--      metadata properties. Created through the management API and attached to an
--      initial access token as a chain.
--   2. dcr_initial_access_tokens: the RFC 7591 section 1.2 initial access tokens
--      (IATs). Minted through the management API, stored SHA-256-hashed (like
--      every other credential), with an expiry and an optional usage limit. Each
--      IAT carries a SNAPSHOT of its attached policy chain (the resolved
--      primitives), so a later edit or deletion of a named policy never changes an
--      already-minted token's behavior.
--   3. dcr_rate_counters: endpoint-local fixed-window counters keyed by source and
--      by IAT, so the registration endpoint can rate limit without a general
--      framework (the M15 layered limiter is out of scope). A counter, not a
--      business mutation, so it is off the audited-write path (like the jti cache).
--   4. A clients ALTER (additive) for the unverified-client quarantine: the
--      quarantined flag, the admin verification timestamp, and the policy-chain
--      snapshot that rides onto the client (and thus its RFC 7592 registration
--      access token) for the client's lifetime, so 7592 updates stay constrained
--      by the SAME policy that bound the original registration.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. All three new tables do all four. The clients ALTER is a
-- pure additive column expand (defaulted or nullable), safe for the old binary.
--
-- Role note (issue #11 peer separation): the DCR abuse-control surface is an
-- OPERATOR function (mint tokens, author policies, verify clients) over DATA-PLANE
-- clients, so it inherently crosses the ironauth_app / ironauth_control peer
-- boundary: an IAT is MINTED by the control plane and CONSUMED by the data plane,
-- and a client is REGISTERED by the data plane and VERIFIED by the control plane.
-- The grants below are therefore deliberately split across both roles, kept as
-- narrow (column-level where it matters) as the two-sided lifecycle allows.

-- ---------------------------------------------------------------------------
-- 1. Named, reusable DCR policy objects (issue #31).
--
-- Each policy is an ordered list of primitives serialized to JSON (the primitives
-- text column). A policy is authored through the management API (control plane),
-- resolved to its primitives when it is attached to an initial access token, and
-- reusable across many tokens. name is unique per scope so a policy can be
-- referenced by name at mint time.
CREATE TABLE dcr_policies (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The operator-facing policy name, unique per scope (the reference handle at
    -- mint time).
    name           text        NOT NULL,
    -- The ordered primitive list as JSON text (force / restrict / reject /
    -- default over metadata properties). Stored as text like clients.jwks, so no
    -- jsonb binding is needed and the engine parses it in Rust.
    primitives     text        NOT NULL,
    created_at     timestamptz NOT NULL,
    CONSTRAINT dcr_policies_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Reusable named objects: one name per scope.
    UNIQUE (tenant_id, environment_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX dcr_policies_scope_idx ON dcr_policies (tenant_id, environment_id);

ALTER TABLE dcr_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcr_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY dcr_policies_tenant_isolation ON dcr_policies
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Policies are authored and resolved ONLY on the control plane (the management API
-- creates them and reads them back when minting a token), so only ironauth_control
-- gets rights here. No DELETE: a policy is a stable reusable object.
GRANT SELECT, INSERT ON dcr_policies TO ironauth_control;

-- ---------------------------------------------------------------------------
-- 2. DCR initial access tokens (RFC 7591 section 1.2, issue #31).
--
-- token_hash is the SHA-256 hex of the plaintext token; the plaintext is returned
-- once at mint and NEVER stored, exactly like a management key secret or a
-- registration access token. policy_chain is the resolved primitive snapshot of
-- the attached policy chain, so the binding is fixed at mint time. expires_at
-- bounds the token's life; max_uses (NULL = unlimited) bounds its use count, and
-- use_count is incremented atomically on each successful registration.
CREATE TABLE dcr_initial_access_tokens (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The SHA-256 hex of the plaintext token. The lookup key; unique because the
    -- token carries 256 bits of entropy. The plaintext is NEVER stored.
    token_hash     text        NOT NULL,
    -- The resolved policy-chain snapshot (the ordered primitive list as JSON
    -- text), or '[]' for an unconstrained token.
    policy_chain   text        NOT NULL DEFAULT '[]',
    -- The last instant the token may be presented (from the application clock
    -- seam).
    expires_at     timestamptz NOT NULL,
    -- The maximum number of registrations this token may authorize; NULL is
    -- unlimited within the expiry.
    max_uses       integer,
    -- How many registrations this token has authorized. Incremented atomically at
    -- consume so a usage limit cannot be raced past.
    use_count      integer     NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    CONSTRAINT dcr_initial_access_tokens_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The token has 256 bits of entropy, so its hash is unique globally and within
    -- any scope.
    UNIQUE (token_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX dcr_initial_access_tokens_scope_idx
    ON dcr_initial_access_tokens (tenant_id, environment_id);

ALTER TABLE dcr_initial_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcr_initial_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY dcr_initial_access_tokens_tenant_isolation ON dcr_initial_access_tokens
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- A token is MINTED on the control plane (management API) and CONSUMED on the data
-- plane (the registration endpoint increments use_count), so both roles need
-- rights: control INSERT + SELECT (mint and list), app SELECT + UPDATE (consume).
-- No DELETE: an expired or exhausted token is left in place (a future reaper may
-- prune, tracked with the M15 limiter work).
GRANT SELECT, INSERT ON dcr_initial_access_tokens TO ironauth_control;
GRANT SELECT, UPDATE ON dcr_initial_access_tokens TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. Endpoint-local registration rate counters (issue #31).
--
-- A fixed-window counter per (scope, rate_key), where rate_key is "src:<source>"
-- or "iat:<id>". window_start is the current window's start (from the application
-- clock seam) and count the hits within it. The upsert either starts a fresh
-- window or increments, atomically, so a limit cannot be raced past. This is a
-- counter cache, not a business mutation, so it is deliberately off the
-- audited-write path (like the jti cache and idempotency store).
CREATE TABLE dcr_rate_counters (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The rate bucket key ("src:<source>" or "iat:<id>").
    rate_key       text        NOT NULL,
    -- The start of the current fixed window (from the application clock seam).
    window_start   timestamptz NOT NULL,
    -- Hits recorded within the current window.
    count          integer     NOT NULL,
    CONSTRAINT dcr_rate_counters_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    PRIMARY KEY (tenant_id, environment_id, rate_key),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE dcr_rate_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcr_rate_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY dcr_rate_counters_tenant_isolation ON dcr_rate_counters
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Driven only by the data-plane registration endpoint: SELECT/INSERT/UPDATE for
-- the upsert-and-increment. No DELETE (a rolled-over window is overwritten in
-- place).
GRANT SELECT, INSERT, UPDATE ON dcr_rate_counters TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 4. Unverified-client quarantine (issue #31). Additive and safe for the old
-- binary: every column defaults to today's behavior (not quarantined, unverified,
-- no policy chain).
--
--   quarantined:      when true, the authorization/consent path IGNORES the
--                     client's implicit/skip_consent first-party carve-outs
--                     (consent is ALWAYS shown) and RESTRICTS the effective
--                     redirect-URI set to the https subset, until an admin
--                     verifies the client. A client from open (or low-trust)
--                     registration starts quarantined.
--   verified_at:      the instant an admin lifted the quarantine (from the
--                     application clock seam), or NULL while unverified.
--   dcr_policy_chain: the resolved policy-chain snapshot (JSON primitive list)
--                     that bound this client's registration. Re-applied to every
--                     RFC 7592 update so the SAME policy constrains the client for
--                     its lifetime; NULL for a client registered without a policy.
ALTER TABLE clients
    ADD COLUMN quarantined      boolean NOT NULL DEFAULT false,
    ADD COLUMN verified_at      timestamptz,
    ADD COLUMN dcr_policy_chain text;

-- The management API (control plane) verifies a client (lifts the quarantine) and
-- reads its verification state. Verifying is an UPDATE of exactly the two
-- quarantine columns; the WHERE and the state read need SELECT on the row. Grant
-- the control plane full-row SELECT (a client secret is stored only as a hash, so
-- this exposes no replayable credential) plus column-level UPDATE, leaving every
-- OTHER clients column read-only to the control plane.
GRANT SELECT ON clients TO ironauth_control;
GRANT UPDATE (quarantined, verified_at) ON clients TO ironauth_control;
