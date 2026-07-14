-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Pushed authorization requests (PAR, RFC 9126, issue #27).
--
-- The PAR endpoint validates a complete authorization request at push time (with
-- EXACTLY the same rules as the authorization endpoint) and, on success, stores it
-- here behind a one-time `par_` reference. The reference is handed back to the
-- client as the urn:ietf:params:oauth:request_uri:<id> value; `/authorize` then
-- consumes it ATOMICALLY exactly once. There is deliberately NO by-reference fetch:
-- a request_uri is only ever this stored row, never dereferenced over the network.
--
-- Two additive (expand) changes land here:
--
--   1. The `pushed_authorization_requests` store: a short-lived, single-use row per
--      pushed request, carrying the serialized authorization parameters, the client
--      the request is bound to, a `consumed_at` single-use marker, and a TTL. The
--      row is consumed by one atomic UPDATE ... WHERE consumed_at IS NULL AND
--      expires_at > now AND client_id = <presenter> RETURNING request_params, so
--      reuse, expiry, and a mismatched presenting client all miss (and a mismatched
--      client can never burn another client's pending request).
--   2. The per-client `clients.require_pushed_authorization_requests` flag (RFC 9126
--      section 5/6): when set, a plain (non-PAR) authorization request from that
--      client is rejected. A nullable-safe additive column defaulting to false, so
--      every existing client is unaffected.
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. pushed_authorization_requests does all four. The clients
-- ALTER is a pure additive column expand (a NOT NULL column with a false DEFAULT,
-- safe for the old binary to ignore).

-- ---------------------------------------------------------------------------
-- 1. The per-client require-PAR flag (RFC 9126 section 5, issue #27).
--
-- When true, the authorization endpoint rejects a plain (non-PAR) request from this
-- client with invalid_request. The environment-wide switch is a config setting; this
-- is the per-client override. Default false, so existing clients keep working.
ALTER TABLE clients
    ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- 2. The pushed-authorization-request store (RFC 9126 section 2, issue #27).
--
-- Tenant-scoped and isolated exactly like the OIDC grant tables: mandatory
-- tenant_id and environment_id, the nonempty-scope CHECK, forced row-level security
-- keyed on the same transaction-local session variables, the same
-- isolation-preserving foreign keys, and reachable only through the data-plane
-- scoped repository (ironauth_app).
CREATE TABLE pushed_authorization_requests (
    -- The par_ scoped identifier; embeds its (tenant, environment). It is the
    -- reference portion of the urn:ietf:params:oauth:request_uri:<id> value, so the
    -- authorization endpoint recovers the scope from a presented request_uri exactly
    -- as it recovers a code's scope from the code.
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The client the pushed request is bound to (the AUTHENTICATED pushing client).
    -- The authorization endpoint enforces that a request_uri presented under a
    -- different client_id is rejected: the atomic consume filters on this column, so
    -- a mismatched presenter matches zero rows and cannot burn the pending request.
    client_id      text        NOT NULL,
    -- The serialized authorization-request parameters, validated at push time with
    -- the SAME rules as /authorize and replayed verbatim when the request_uri is
    -- consumed. Opaque to the store (an application-owned JSON document); the store
    -- shape does not leak into the endpoint, so a later cache-accelerated backend
    -- (M15) needs no protocol change.
    request_params text        NOT NULL,
    -- The single-use marker: NULL until the request_uri is consumed at /authorize,
    -- set to the consume instant on the first (and only) successful use.
    consumed_at    timestamptz,
    -- The request_uri expiry, from the application clock seam (never the database
    -- clock), so expiry is deterministic under a manual clock in tests. Short-lived
    -- and bounded (oidc.par_ttl_secs).
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pushed_authorization_requests_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX pushed_authorization_requests_scope_idx
    ON pushed_authorization_requests (tenant_id, environment_id);

ALTER TABLE pushed_authorization_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pushed_authorization_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY pushed_authorization_requests_tenant_isolation ON pushed_authorization_requests
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT and INSERT to push, and UPDATE for the atomic single-use consume
-- (SET consumed_at). No DELETE grant: like the authorization_codes table, a
-- consumed or expired row is left in place (short-lived and query-filtered by
-- consumed_at/expires_at), never mutated or removed in place beyond the consume.
GRANT SELECT, INSERT, UPDATE ON pushed_authorization_requests TO ironauth_app;
