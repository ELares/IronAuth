-- The Postgres-backed hot state: the implementation that makes the accelerator OPTIONAL (#146).
--
-- The covenant is that IronAuth is complete on PostgreSQL alone. `ironauth-hot` declares one
-- interface for everything an accelerator could hold; this table is the implementation that is
-- always present behind it, so "IronCache unreachable" is a latency change and never a
-- behaviour change. Keycloak keeps one-time-use and login-failure state in Infinispan, which is
-- the mandatory-cluster dependency the covenant forbids; this is the other answer.
--
-- WHY A TABLE AND NOT THE TABLES THE DATA ALREADY LIVES IN. Most hot-state uses cache something
-- derived from a row elsewhere (a JWKS, a tenant config, an introspection result), and for
-- those this is a cache of a cache and would be pointless. The uses that need it are the ones
-- with no home of their own: a single-use marker, a rotation lock, a counter. They are all the
-- same shape -- a key, some bytes, an expiry -- and giving each its own table would be six
-- migrations describing one idea.
--
-- EVERY EXPIRY COMPARISON TAKES THE INSTANT AS A PARAMETER, never `now()`. The application
-- clock seam is what makes expiry deterministic under a manual clock, and a statement that read
-- the database clock would be the one place in this schema that could not be tested that way.
-- `scripts/invariant-lints.sh` cannot see into SQL, so this is a rule the reviewer holds.

CREATE TABLE hot_state (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The `HotUse` name, from `ironauth_hot::registry`. It is part of the key rather than a
    -- decoration: two uses may legitimately choose the same key string (a subject id is a
    -- plausible key for both a rate counter and a pending marker), and without this column one
    -- use's entries would answer the other's reads. It is also what a per-use sweep, a
    -- per-use quota and a per-use disable all filter on.
    use_name       text        NOT NULL,
    -- The caller's key, opaque here.
    key            text        NOT NULL,
    value          bytea       NOT NULL,
    -- When this entry stops being readable. A row at or past this instant is a MISS, and the
    -- sweep may delete it; the two rules are separate on purpose, so a sweep that has not run
    -- yet can never make an expired entry readable.
    expires_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, environment_id, use_name, key),

    CONSTRAINT hot_state_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT hot_state_use_name_bounded
        CHECK (use_name <> '' AND octet_length(use_name) <= 64),
    -- A KEY IS BOUNDED because an unauthenticated caller can influence one: a device code, a
    -- flow id, a subject. 512 bytes is far past any key the registry's uses need and far short
    -- of a row a flood could make expensive. See `hot_state_value_bounded` for the other half.
    CONSTRAINT hot_state_key_bounded
        CHECK (key <> '' AND octet_length(key) <= 512),
    -- 64 KiB. Nothing in the registry stores anything near it; the bound is here because this
    -- table is reachable from pre-authentication paths, which is the Dex #1292 shape (an
    -- unauthenticated flow-row DoS, open since 2018). A quota on the NUMBER of rows is the
    -- other half and arrives with the pre-auth hygiene slice; this caps one row's cost.
    CONSTRAINT hot_state_value_bounded
        CHECK (octet_length(value) <= 65536),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE hot_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE hot_state FORCE ROW LEVEL SECURITY;

CREATE POLICY hot_state_scope ON hot_state
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The sweep's index, SCOPED, because the sweep is scoped.
--
-- A deployment-wide `DELETE FROM hot_state WHERE expires_at <= $1` is the shape that first
-- suggests itself and `ironauth_app` cannot run it: this table is FORCE ROW LEVEL SECURITY, so
-- every statement that role issues is filtered to one tenant and environment whatever it says.
-- Sweeping deployment-wide would mean a second role, which is a real cost (a DSN, a grant, a
-- rotation) to buy an efficiency this table does not need -- and the scoped grain is the one
-- the per-tenant quotas in the same issue want anyway.
--
-- So the leading columns are the scope and the trailing one is the expiry, which is exactly the
-- order `HotStateSweep` reads them in.
CREATE INDEX hot_state_scope_expires_at
    ON hot_state (tenant_id, environment_id, expires_at);

-- ALL FOUR VERBS, and each is load-bearing.
--
-- UPDATE is not a convenience: it is how `put_if_absent` claims a key whose previous entry has
-- EXPIRED. `INSERT ... ON CONFLICT DO NOTHING` would read a dead row as a live holder and
-- refuse the claim for ever, which for a rotation lock is a lock nobody can ever take again.
-- The guarded `DO UPDATE ... WHERE hot_state.expires_at <= $now` is what makes expiry and
-- atomicity one statement instead of a read, a decision, and a race.
--
-- DELETE is both the sweep and revocation: an introspection entry is deleted when the token is
-- revoked rather than waited out, and a single-use marker is deleted when a legitimate retry
-- must be allowed again.
GRANT SELECT, INSERT, UPDATE, DELETE ON hot_state TO ironauth_app;
