-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Headless flow API state (issue #84).
--
-- The flow engine generalizes the bootstrap interaction pages into one persisted,
-- machine readable flow object (a state machine plus a typed node/message renderer)
-- consumed identically by the browser and native JSON transports. This migration lands
-- the one server side row that holds a flow's position between submissions:
--
--   flows: one row per in progress journey (login, registration, MFA, recovery). It
--     holds:
--     - a scope embedded `flw_` id (embeds its (tenant, environment), so a row minted
--       in one scope parses as a uniform not found under another);
--     - journey / transport: the journey this row drives and the transport it was
--       created on (immutable after creation, so a flow created for a native JSON
--       client is never continued as a browser flow or the reverse);
--     - state: the serialized state machine position plus the node scratch the next
--       render needs. Opaque application JSON, never interpreted by SQL;
--     - submit_token: the API transport CSRF handle, a high entropy value minted from
--       the entropy seam and ROTATED on every successful transition, so a captured
--       token is single use per step. The browser transport does not use it (it has the
--       SameSite cookie plus the same origin header check);
--     - transient_payload: arbitrary client supplied context (campaign ids, device
--       hints) carried through the flow into hooks and message templates. It lives ONLY
--       in this column and is NEVER copied onto an identity table, so it cannot persist
--       on the identity by construction (issue #84 acceptance);
--     - return_to: the pending LOCAL `/authorize?...` resume target, so a completed
--       flow resumes the authorization request exactly where it paused;
--     - contract_version: the flow contract version this row was minted under;
--     - consumed_at: the single use completion latch (NULL until completed), so a
--       replayed completed flow matches no consumable row;
--     - expires_at: the TTL from the application clock seam (never the database clock),
--       so expiry is deterministic under a manual clock in tests. Short lived, bounded.
--
-- Migration safety obligation (see migrate.rs): the NEW tenant scoped table ENABLES and
-- FORCES row level security, adds the (tenant, environment) isolation policy, adds the
-- nonempty scope CHECK, and is registered in scripts/query-audit.sh. Every statement is
-- additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The per environment headless flow state store (issue #84).
CREATE TABLE flows (
    -- The flw_ scoped identifier; embeds its (tenant, environment).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The journey this row drives: login | registration | mfa | recovery.
    journey            text        NOT NULL,
    -- The transport this flow was created on: browser | api. Immutable after creation.
    transport          text        NOT NULL,
    -- The serialized state machine position plus node scratch. Opaque application JSON.
    state              jsonb       NOT NULL,
    -- The API transport CSRF handle, rotated on every successful transition. The browser
    -- transport leans on the SameSite cookie plus the same origin header check instead.
    submit_token       text        NOT NULL,
    -- Arbitrary client supplied context carried through the flow into hooks and message
    -- templates. Lives ONLY here; NEVER copied onto an identity table.
    transient_payload  jsonb,
    -- The pending LOCAL /authorize?... resume target.
    return_to          text,
    -- The flow contract version this row was minted under.
    contract_version   integer     NOT NULL,
    -- The single use completion latch: NULL until the flow completes.
    consumed_at        timestamptz,
    -- The row expiry, from the application clock seam (never the database clock), so it
    -- is deterministic under a manual clock in tests. Short lived and bounded.
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT flows_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The API transport consumes/advances BY submit_token within scope, so the token is
-- unique per (tenant, environment).
CREATE UNIQUE INDEX flows_submit_token_idx
    ON flows (tenant_id, environment_id, submit_token);

ALTER TABLE flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE flows FORCE ROW LEVEL SECURITY;
CREATE POLICY flows_tenant_isolation ON flows
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT and INSERT to persist a flow, and UPDATE for the atomic per step transition
-- (rotate submit_token, advance state) and the single use completion latch (SET
-- consumed_at). No DELETE grant: like authorization_codes and federation_login_states, a
-- consumed or expired row is left in place (short lived and query filtered by
-- consumed_at/expires_at), never removed, so a leaked row cannot be deleted to cover a
-- replay either.
GRANT SELECT, INSERT, UPDATE ON flows TO ironauth_app;
