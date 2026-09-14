-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The Postgres-backed hot state: the implementation that makes the accelerator OPTIONAL (#146).
--
-- The covenant is that IronAuth is complete on PostgreSQL alone. `ironauth-hot` declares one
-- interface for everything an accelerator could hold; this table is the implementation that is
-- always present behind it, so "IronCache unreachable" is a latency change and never a
-- behaviour change. Keycloak keeps one-time-use and login-failure state in Infinispan, which is
-- the mandatory-cluster dependency the covenant forbids; this is the other answer.
--
-- WHY ONE TABLE AND NOT THE TABLES THE DATA ALREADY LIVES IN. Three of the registry's seven
-- uses cache something derived from a row elsewhere (JWKS, tenant config, introspection), and
-- for those a Postgres-backed entry is a cache of a cache: the implementation stores them, but
-- a deployment with no accelerator gains nothing by it. The other four have no home of their
-- own -- two counters, a single-use marker and a rotation lock -- and they are all the same
-- shape: a key, some bytes, an expiry. Giving each its own table would be four migrations
-- describing one idea, and a fifth the first time the registry grew.
--
-- EVERY EXPIRY COMPARISON TAKES THE INSTANT AS A PARAMETER, never `now()`. The application
-- clock seam is what makes expiry deterministic under a manual clock, and it is the convention
-- the rest of this schema already follows. `scripts/invariant-lints.sh` enforces the Rust half
-- and cannot see into SQL, so inside a statement this is a rule the reviewer holds.

CREATE TABLE hot_state (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The `HotUse` name, from `ironauth_hot::registry`. It is part of the key rather than a
    -- decoration: two uses may legitimately choose the same key string (a subject id is a
    -- plausible key for both a rate counter and a pending marker), and without this column one
    -- use's entries would answer the other's reads. That collision is the whole justification,
    -- and it is tested.
    --
    -- The per-use sweep, per-use quota and per-use disable that #146 also asks for would filter
    -- on this column, and NONE OF THEM EXIST YET -- the sweep that does exist is scope-wide and
    -- ignores it. The column is not being added for them; it is being added because the read
    -- would be wrong without it.
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
    -- A KEY IS BOUNDED because the uses this table exists for take a key an unauthenticated
    -- caller influences: a device code, a flow id, a subject. 512 bytes is far past any key the
    -- registry's uses need and far short of a row a flood could make expensive.
    --
    -- NOTHING OUTSIDE THE TESTS REACHES THIS TABLE YET -- the registry's uses are declared and
    -- not yet wired to their call sites -- so this bound is being set BEFORE the traffic rather
    -- than after it. That is the only order in which a bound on an unauthenticated input is
    -- cheap to choose. See `hot_state_value_bounded` for the other half.
    CONSTRAINT hot_state_key_bounded
        CHECK (key <> '' AND octet_length(key) <= 512),
    -- 64 KiB. Nothing in the registry stores anything near it; the bound is here because the
    -- uses this table is for will be reached from pre-authentication paths, which is the Dex
    -- #1292 shape (an unauthenticated flow-row DoS, open since 2018). This caps ONE ROW'S COST
    -- and nothing else: a quota on the NUMBER of rows is the other half of that defence and
    -- does not exist yet -- it arrives with the pre-auth hygiene slice of #146. Until it does,
    -- an anonymous flood is bounded in bytes per row and unbounded in rows.
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
-- So the leading columns are the scope and the trailing one is the expiry, which is the order
-- `HotStateRepo::sweep_expired` reads them in. (An earlier draft of this comment named a
-- `HotStateSweep` type; no such type was ever written.)
CREATE INDEX hot_state_scope_expires_at
    ON hot_state (tenant_id, environment_id, expires_at);

-- ALL FOUR VERBS, and each is load-bearing.
--
-- UPDATE has TWO producers, and naming only one would invite a future slice to drop it:
--
--   * `put` is `INSERT ... ON CONFLICT DO UPDATE` with no guard, because its contract is to
--     replace whatever was there. Postgres checks the UPDATE privilege when it PLANS such a
--     statement, whether or not a conflict occurs, so this is required even for a first write.
--   * `put_if_absent` is the guarded form, and it is how a key whose previous entry has EXPIRED
--     is claimed. `INSERT ... ON CONFLICT DO NOTHING` would read a dead row as a live holder
--     and refuse the claim for ever, which for a rotation lock is a lock nobody can ever take
--     again. The guarded `DO UPDATE ... WHERE hot_state.expires_at <= $now` makes expiry and
--     atomicity one statement instead of a read, a decision, and a race.
--
-- DELETE is both the sweep and revocation: an introspection entry is deleted when the token is
-- revoked rather than waited out, and a single-use marker is deleted when a legitimate retry
-- must be allowed again.
GRANT SELECT, INSERT, UPDATE, DELETE ON hot_state TO ironauth_app;
