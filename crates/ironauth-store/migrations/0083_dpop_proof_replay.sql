-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The cross-node DPoP proof jti replay store: the dpop_proof_replay table (issue
-- #368, resource-server verify).
--
-- A DPoP proof presented at a protected resource (the userinfo endpoint) carries a
-- jti the server must not accept twice inside the proof freshness window (RFC 9449
-- section 11.1). Unlike the token endpoint, where the proof rides a single-use
-- authorization code that already bounds a replay, at the resource server the proof
-- rides a REUSABLE access token presented across every instance, so the in-memory
-- per-instance cache is not enough: a proof replayed against a DIFFERENT instance
-- inside the window would otherwise pass. This shared table is the cross-instance
-- single-use latch: the first presentation of a (jkt, jti) in a scope RECORDS it,
-- and a second identical (jkt, jti) within the TTL is refused as a replay.
--
--   dpop_proof_replay: one row per recorded (jkt, jti) inside its freshness window.
--     - jkt: the RFC 7638 thumbprint of the proof key. The latch is keyed by
--       (tenant, environment, jkt, jti) so two DIFFERENT proof keys that improbably
--       chose the same jti do not shadow each other, and a jti is only ever a replay
--       for the SAME key, mirroring the in-memory cache key;
--     - jti: the proof's unique identifier, an opaque client-chosen value. It is NOT
--       a secret and NOT personal data, so it is stored as plaintext text;
--     - expires_at: the last instant the proof could still pass the freshness window
--       (now plus the iat leeway plus the skew plus a one-second cushion), from the
--       application clock seam, so the on-insert prune is deterministic under a
--       manual clock in tests. The prune admits a row only while unexpired: a stale
--       jti past this boundary is simply reclaimed and a re-used jti past the window
--       is accepted again, exactly as a fresh proof would be.
--
--     Runtime data (issue #41): a DPoP proof jti is dynamic per-environment
--     single-use anti-replay state (like a client_assertion jti), NEVER promotable
--     config, so it STRUCTURALLY never enters a config snapshot and carries no
--     first-class ResourceType variant.
--
-- The PRIMARY KEY (tenant_id, environment_id, jkt, jti) is the STRUCTURAL single-use
-- invariant: a given (jkt, jti) exists at most once in a scope, so the guarded insert
-- either wins (first use) or collides (replay). The repository's check-and-record
-- method runs the guarded write, so exactly one concurrent request wins.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant scoped table ENABLES
-- and FORCES row level security, adds the (tenant, environment) isolation policy, adds
-- the nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every
-- statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The cross-node DPoP proof jti replay store (issue #368).
CREATE TABLE dpop_proof_replay (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The RFC 7638 thumbprint of the proof key. Part of the single-use key so a jti
    -- is only ever a replay under the SAME key.
    jkt            text        NOT NULL,
    -- The proof's unique identifier (a client-chosen token identifier). Not a secret
    -- and not personal data; stored as plaintext text.
    jti            text        NOT NULL,
    -- The last instant the proof could still pass the freshness window (now plus the
    -- iat leeway plus the skew plus a one-second cushion), from the application clock
    -- seam, so the on-insert prune is deterministic under a manual clock in tests.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dpop_proof_replay_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Single use: a second presentation of the same (jkt, jti) in this scope is a
    -- primary-key conflict, which the recording path maps to REPLAY.
    PRIMARY KEY (tenant_id, environment_id, jkt, jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The prune path scans expired rows within scope by expiry.
CREATE INDEX dpop_proof_replay_expiry_idx
    ON dpop_proof_replay (tenant_id, environment_id, expires_at);

ALTER TABLE dpop_proof_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpop_proof_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY dpop_proof_replay_tenant_isolation ON dpop_proof_replay
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to check membership, INSERT to record a new (jkt, jti), and DELETE for the
-- on-insert prune of already-expired rows. The ONLY DELETE the repository issues
-- removes rows whose expires_at (past the freshness window plus the cushion) has
-- passed, so the grant cannot be used to reopen a replay window for a still-fresh
-- proof. There is deliberately no UPDATE grant: a replay row is never mutated in place.
GRANT SELECT, INSERT, DELETE ON dpop_proof_replay TO ironauth_app;
