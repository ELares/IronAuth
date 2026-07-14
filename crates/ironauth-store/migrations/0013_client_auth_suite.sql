-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The JWT-assertion client-authentication suite (issue #25).
--
-- This migration lands three additive (expand) changes that complete the client
-- authentication suite with the JWT-assertion methods and uniform failure
-- hygiene:
--
--   1. The clients registration surface for asymmetric client authentication
--      (private_key_jwt): the client's inline `jwks`, its `jwks_uri`, and the
--      per-client `token_endpoint_auth_signing_alg` allowlist. This is the same
--      registration-facing shape Dynamic Client Registration (#30) reuses.
--   2. The cross-node single-use `jti` replay cache (client_assertion_jtis): a
--      shared-database UNIQUE constraint makes a second use of an assertion's jti
--      a conflict, which is correct across nodes because every node inserts into
--      the same row space.
--   3. The out-of-band client-authentication diagnostics sink
--      (client_auth_diagnostics): the rich, structured record of a failed client
--      authentication (method, reason, key id, alg) for the M9 admin view, kept
--      OFF the wire so an authentication failure reveals nothing about which check
--      failed.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Both new tables do all four. The clients ALTER is a pure
-- additive column expand (nullable columns, safe for the old binary to ignore).

-- ---------------------------------------------------------------------------
-- 1. Client key/algorithm registration for private_key_jwt (issue #25).
--
-- A client that authenticates with private_key_jwt registers its verification
-- keys either inline (`jwks`, a JWK Set JSON document) or by reference
-- (`jwks_uri`, fetched through the SSRF-hardened fetcher). At most one is set. The
-- optional `token_endpoint_auth_signing_alg` pins the single JWS algorithm the
-- client's assertions must be signed with (a per-client allowlist); when unset,
-- the supported asymmetric set applies. All three are nullable, so an existing
-- secret-based or public client is entirely unaffected.
ALTER TABLE clients ADD COLUMN jwks text;
ALTER TABLE clients ADD COLUMN jwks_uri text;
ALTER TABLE clients ADD COLUMN token_endpoint_auth_signing_alg text;

-- A client registers keys inline OR by reference, never both: a document that set
-- both would make key resolution ambiguous.
ALTER TABLE clients ADD CONSTRAINT clients_client_keys_exclusive
    CHECK (NOT (jwks IS NOT NULL AND jwks_uri IS NOT NULL));

-- A private_key_jwt client MUST register EXACTLY ONE key source (jwks XOR
-- jwks_uri): a keyless private_key_jwt client would register but fail EVERY request
-- silently (no key to verify its assertion against), which is a misconfiguration
-- that must fail LOUD at registration, not per request. The XOR here also subsumes
-- the exclusivity CHECK above for a private_key_jwt row. The constraint is scoped to
-- private_key_jwt, so a secret-based or public client (both key columns NULL) and a
-- client_secret_jwt client (which keys no assertion) are unaffected.
ALTER TABLE clients ADD CONSTRAINT clients_private_key_jwt_has_one_key
    CHECK (
        token_endpoint_auth_method <> 'private_key_jwt'
        OR (jwks IS NOT NULL) <> (jwks_uri IS NOT NULL)
    );

-- ---------------------------------------------------------------------------
-- 2. The cross-node single-use jti replay cache (issue #25).
--
-- An accepted JWT client assertion carries a `jti` that MUST be single use (RFC
-- 7523 section 3). Recording it is an INSERT; a UNIQUE conflict on insert is a
-- REPLAY and the assertion is rejected. Because every server node inserts into
-- this ONE shared table, the database's uniqueness enforces single use ACROSS
-- nodes: two nodes racing the same jti cannot both insert it.
--
-- `expires_at` is the last instant the assertion could still be replayed. Acceptance
-- (enforce_exp) floors `now` to WHOLE seconds and rejects only once
-- `now_secs > exp + skew`, so an assertion stays acceptable for the ENTIRE wall-clock
-- second [exp+skew, exp+skew+1). The recorder therefore stores `exp + skew + 1s` (one
-- second BEYOND the last acceptable second), NOT the bare `exp + skew`: pruning runs
-- at MICROSECOND precision, so a bare `exp + skew` row would be deleted partway through
-- that final acceptable second, re-inserted as fresh, and let the single-use assertion
-- replay. With the +1s margin the retained row strictly OUTLASTS acceptance, so pruning
-- can never remove a jti whose assertion is still acceptable and thus can never open a
-- replay window.
CREATE TABLE client_assertion_jtis (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The client the assertion authenticated as (its iss/sub, which equal the
    -- client_id). A jti is unique PER client (RFC 7523), so the client is part of
    -- the single-use key.
    client_id      text        NOT NULL,
    -- The assertion's jti (a client-chosen token identifier).
    jti            text        NOT NULL,
    -- The last replayable instant (assertion exp + skew + 1s; see the note above on
    -- the +1s margin), from the application clock seam, so pruning is deterministic
    -- under a manual clock in tests.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT client_assertion_jtis_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Single use: a second presentation of the same (client, jti) in this scope is
    -- a primary-key conflict, which the recording path maps to REPLAY.
    PRIMARY KEY (tenant_id, environment_id, client_id, jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The prune path scans expired rows within scope by expiry.
CREATE INDEX client_assertion_jtis_expiry_idx
    ON client_assertion_jtis (tenant_id, environment_id, expires_at);

ALTER TABLE client_assertion_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_assertion_jtis FORCE ROW LEVEL SECURITY;
CREATE POLICY client_assertion_jtis_tenant_isolation ON client_assertion_jtis
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to check membership, INSERT to record a new jti, and DELETE for the
-- on-insert prune of already-expired rows. The ONLY DELETE the repository issues
-- removes rows whose expires_at (assertion exp + skew + 1s) has passed, so the grant
-- cannot be used to reopen a replay window for a still-valid assertion. There is
-- deliberately no UPDATE grant: a jti row is never mutated in place.
GRANT SELECT, INSERT, DELETE ON client_assertion_jtis TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. The out-of-band client-authentication diagnostics sink (issue #25).
--
-- A client-authentication FAILURE returns an opaque `invalid_client` on the wire
-- (no oracle for which check failed). The rich, structured detail (the method
-- attempted, the bounded-cardinality failure reason, and the assertion header's
-- key id and algorithm) is recorded HERE instead, for the future M9 admin view.
-- Only the RECORDING lands in this issue; the admin rendering is out of scope.
--
-- Insert-and-prune, like the jti cache: SELECT, INSERT, and a bounded on-insert
-- DELETE, never UPDATE. A diagnostic is a log entry, not a business mutation, so
-- like idempotency_keys it is deliberately OFF the audited-write path (auditing a
-- diagnostic would be circular); it stays confined to the repository module and
-- RLS-scoped so it is written only within its own (tenant, environment).
--
-- Retention (bounded growth). Every FAILED authentication writes one row with some
-- attacker-influenced text (a best-effort client_id, and the assertion header alg /
-- kid). At the token endpoint this is bounded (a diagnostic is written only after a
-- valid, loaded authorization code gates the request), but issue #22
-- introspection/revocation reuses the SAME authenticate_client seam PRE-grant, where
-- an UNAUTHENTICATED caller reaches it. Without retention that would be one
-- unbounded, persistent row per request. `expires_at` (occurred_at + a fixed
-- retention window; see DIAGNOSTIC_RETENTION_MICROS in repository.rs) bounds the
-- table: the recorder prunes expired rows before each insert, exactly like the jti
-- cache. This is a growth bound only, NOT rate limiting.
CREATE TABLE client_auth_diagnostics (
    -- A random per-row identifier (drawn from the application entropy seam), so a
    -- row is addressable without leaking an ordering or a count.
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The client identifier the attempt claimed (best effort: it may be an
    -- unknown or unparseable value on a failed attempt).
    client_id      text        NOT NULL,
    -- The token-endpoint authentication method the attempt used.
    auth_method    text        NOT NULL,
    -- The bounded-cardinality failure reason (see ClientAuthDiagnosticReason). No
    -- attacker-controlled free text, so it is safe as a metric-like dimension.
    failure_reason text        NOT NULL,
    -- The assertion header's key id and algorithm, when the attempt presented a
    -- JWT assertion; NULL for a secret-based attempt or an unparseable header.
    key_id         text,
    signing_alg    text,
    -- When the attempt happened, from the application clock seam (never the
    -- database clock), so it is deterministic under a manual clock in tests.
    occurred_at    timestamptz NOT NULL,
    -- When this row may be pruned (occurred_at + the fixed retention window), from
    -- the application clock seam, so the on-insert prune is deterministic under a
    -- manual clock. Bounds the table so #22's pre-grant reuse of the seam cannot grow
    -- it without limit.
    expires_at     timestamptz NOT NULL,
    -- When the row was persisted, from the database clock. Operational metadata
    -- only; occurred_at is the authoritative event time.
    recorded_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT client_auth_diagnostics_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX client_auth_diagnostics_scope_idx
    ON client_auth_diagnostics (tenant_id, environment_id, occurred_at);

-- The on-insert prune scans expired rows within scope by expiry.
CREATE INDEX client_auth_diagnostics_expiry_idx
    ON client_auth_diagnostics (tenant_id, environment_id, expires_at);

ALTER TABLE client_auth_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_auth_diagnostics FORCE ROW LEVEL SECURITY;
CREATE POLICY client_auth_diagnostics_tenant_isolation ON client_auth_diagnostics
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to read for the M9 view, INSERT to record, and DELETE for the on-insert
-- retention prune of already-expired rows (the ONLY DELETE the repository issues,
-- exactly like the jti cache). There is deliberately no UPDATE grant: a diagnostic is
-- never mutated in place.
GRANT SELECT, INSERT, DELETE ON client_auth_diagnostics TO ironauth_app;
