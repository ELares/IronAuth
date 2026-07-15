-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Tenant lifecycle API with residency attributes (issue #46).
--
-- The four-level resource model (issue #41) can already create, list, get, and
-- soft-deactivate tenants and environments. This migration adds the LIFECYCLE
-- state machine and the RESIDENCY attributes those resources were missing, in one
-- expand-phase change:
--
--   1. A lifecycle STATUS on tenants: 'active' or 'suspended'. Suspension is a
--      reversible operator action that stops the tenant serving data-plane traffic
--      while keeping its data intact and its rows visible to the control plane; a
--      resume flips it back with no data loss. Suspension is DISTINCT from the
--      soft-delete tombstone (deleted_at, 0003): a suspended tenant is live but
--      fenced, a deleted tenant is offboarded. The state machine (only valid
--      transitions) is enforced above this column in the repository.
--
--   2. A RESIDENCY attribute on tenants: home_region, the tenant's data-residency
--      region, recorded before any cross-region execution exists (M15 executes on
--      it). It is validated against the operator's configured region set at the API
--      layer and is immutable after create (there is no UPDATE path for it, and the
--      control role's grant below never covers it). Recording it now avoids a
--      painful retrofit when multi-region replication lands.
--
--   3. environment_states: a new tenant-scoped table recording each
--      (tenant, environment)'s data-plane SERVING status ('active' or 'suspended').
--      Suspension is decided at the tenant (control) plane, but the fence is
--      enforced on the DATA plane, which authenticates as the low-privilege
--      ironauth_app role and deliberately CANNOT read the tenants/environments level
--      tables (those are the control plane's, 0003). So the serving decision is
--      mirrored into this scoped, RLS-forced table that the data plane CAN read
--      under its own (tenant, environment) scope: the OIDC issuer-load path consults
--      it and fails closed for a suspended scope. A tenant suspend/resume cascades
--      to every one of its environments' rows, exactly as the soft-delete cascade
--      does for management credentials (0003).
--
--   4. A control-plane crypto-shred grant on tenant_keks (0028). Offboarding a
--      tenant (its DELETE) must make the tenant's PII cryptographically
--      unrecoverable, not merely soft-deleted, by DESTROYING its per-(tenant,
--      environment) key-encryption keys (the envelope crypto-shred, issue #48).
--      That destroy is folded into the SAME audited transaction as the tenant
--      deactivation, which runs as ironauth_control, so the control role needs the
--      exact crypto-shred capability on tenant_keks: SELECT (the shred UPDATE reads
--      tenant_id/environment_id/status in its WHERE) plus a COLUMN-SCOPED UPDATE
--      over only the three columns the shred rewrites (the #31 lesson: never a
--      table-wide UPDATE). It gets no INSERT and no DELETE: it can destroy a KEK but
--      never mint one (that stays the data plane's) and never remove the retained
--      evidence row.
--
-- Migration safety obligation (see migrate.rs): the new tenant-scoped table
-- environment_states ENABLEs and FORCEs row-level security, adds the
-- (tenant, environment) isolation policy, adds the nonempty-scope CHECK, and is
-- registered in scripts/query-audit.sh. All four hold below. This whole migration
-- is additive (new columns, a new table, a new grant), so it is an expand.

-- ---------------------------------------------------------------------------
-- The tenant lifecycle status.
--
-- 'active' is the day-one state; 'suspended' is the reversible fenced state. The
-- CHECK makes any other value impossible, so the state machine never has to defend
-- against a stray string. The column is NOT NULL DEFAULT 'active', so it fills
-- existing rows and every future INSERT that omits it lands 'active'. It is
-- distinct from deleted_at: deletion is the terminal offboarding tombstone, while
-- status toggles between live-and-serving and live-but-fenced.
ALTER TABLE tenants
    ADD COLUMN status text NOT NULL DEFAULT 'active';
ALTER TABLE tenants
    ADD CONSTRAINT tenants_status_valid CHECK (status IN ('active', 'suspended'));

-- ---------------------------------------------------------------------------
-- The tenant residency attribute.
--
-- home_region is the tenant's recorded data-residency region (for example
-- 'eu-west' or 'us-east'). It is a RECORDED attribute only in this issue: nothing
-- routes or replicates by region yet. It is validated against the operator's
-- configured region set at the API layer and is IMMUTABLE after create: no
-- repository path issues an UPDATE of home_region, AND the column-scoped control
-- grant below excludes it, so Postgres refuses any such write fail closed. Nullable
-- so a deployment that pins no region records none, rather than inventing a default
-- residency.
ALTER TABLE tenants
    ADD COLUMN home_region text;

-- ---------------------------------------------------------------------------
-- The per-environment residency region pin.
--
-- region is each environment's recorded data-residency region, the per-component
-- pin the issue's residency schema requires ALONGSIDE the tenant home_region. Like
-- home_region it is a RECORDED attribute only (nothing routes or replicates by it
-- yet, M15 executes), validated against the operator's configured region set at the
-- API layer, and IMMUTABLE after create: the control role's UPDATE grant below is
-- column-scoped to exclude it, so no path (errant or future) can rewrite it. Nullable
-- so an environment created without a pin records none rather than inventing one.
ALTER TABLE environments
    ADD COLUMN region text;

-- ---------------------------------------------------------------------------
-- The offboarding pipeline terminal marker.
--
-- A tenant delete (offboard) is now a GRACE soft-delete: it sets deleted_at (the
-- grace tombstone), fences the data plane, and keeps every key INTACT so a restore
-- inside the configured retention window brings the tenant back with no data loss.
-- purged_at is the TERMINAL marker: the hard-delete stage, permitted only after the
-- retention window elapses, stamps it and destroys the tenant's envelope keys (the
-- crypto-shred, deferred to that terminal stage per the issue's out-of-scope). A
-- purged tenant can no longer be restored. Nullable: null in grace, set at the
-- terminal hard deletion. The ordinary delete NEVER shreds; only the purge does.
ALTER TABLE tenants
    ADD COLUMN purged_at timestamptz;

-- ---------------------------------------------------------------------------
-- Residency immutability, enforced by a COLUMN-SCOPED control-plane UPDATE grant.
--
-- home_region (tenants) and region (environments) are immutable after create. The
-- issue wants that enforced by CODE, not merely by the absence of an update path. So
-- narrow the control role's table-wide UPDATE on these two LEVEL tables (0003) to
-- exactly the columns a lifecycle transition legitimately rewrites, mirroring the
-- column-scoped grants the clients (0018), sessions (0022), and organizations (0027)
-- surfaces already use. After this a control-plane UPDATE of home_region or region is
-- refused by Postgres itself (fail closed), so the residency pin cannot be rewritten
-- even by an errant future path. The control role updates on tenants are exactly the
-- lifecycle status flip, the grace/restore deleted_at, and the terminal purged_at; on
-- environments it is exactly the grace/restore deleted_at. INSERT (which records the
-- pins at create) is untouched.
REVOKE UPDATE ON tenants FROM ironauth_control;
GRANT UPDATE (status, deleted_at, purged_at) ON tenants TO ironauth_control;
REVOKE UPDATE ON environments FROM ironauth_control;
GRANT UPDATE (deleted_at) ON environments TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The per-(tenant, environment) data-plane serving state.
--
-- A tenant-scoped table isolated exactly like clients (0001): mandatory tenant_id
-- and environment_id, the nonempty-scope CHECK, forced row-level security keyed on
-- the same transaction-local session variables, and the same isolation-preserving
-- foreign keys. Its PRIMARY KEY is the scope itself, so a (tenant, environment)
-- names at most one serving-state row.
--
-- serving_status 'active' means the data plane serves this scope; 'suspended' means
-- the data plane fences it (the OIDC issuer-load path returns no entry, a
-- fail-closed refusal). A missing row reads as active (a scope provisioned before
-- this table existed serves normally); the control plane provisions a row for every
-- environment at create so the steady state is explicit.
CREATE TABLE environment_states (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- 'active' (served) or 'suspended' (data-plane fenced). Reversible.
    serving_status text        NOT NULL DEFAULT 'active',
    -- The last transition instant, from the application clock seam.
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, environment_id),
    CONSTRAINT environment_states_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT environment_states_serving_status_valid
        CHECK (serving_status IN ('active', 'suspended')),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE environment_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_states FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_states_tenant_isolation ON environment_states
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane (ironauth_app) reads the serving state to fence a suspended scope;
-- it never writes it. The CONTROL plane (ironauth_control) provisions a row on
-- create (INSERT) and flips it on suspend/resume (a COLUMN-SCOPED UPDATE over only
-- serving_status and updated_at, never a table-wide UPDATE, the #31 lesson). Neither
-- role may DELETE a serving-state row.
GRANT SELECT ON environment_states TO ironauth_app;
GRANT SELECT, INSERT ON environment_states TO ironauth_control;
GRANT UPDATE (serving_status, updated_at) ON environment_states TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The control-plane crypto-shred grant on tenant_keks (0028).
--
-- The TERMINAL hard-delete stage (purge) destroys a tenant's per-scope KEKs in the
-- same audited transaction as the terminal deactivation (which runs as
-- ironauth_control). The ordinary offboard delete NEVER shreds (it keeps the keys
-- intact so a restore inside the retention window loses no data); only the purge,
-- permitted after the window elapses, crypto-shreds. So the control role
-- gets exactly the crypto-shred capability and nothing more: SELECT (the shred
-- reads tenant_id/environment_id/status in its WHERE) and a COLUMN-SCOPED UPDATE
-- over only the wrapped-key bytes, the status, and the destroyed_at instant. It
-- gets no INSERT (minting a KEK stays the data plane's) and no DELETE (the
-- destroyed KEK row is retained as evidence). The control role is never a superuser
-- or table owner, so FORCE row-level security on tenant_keks applies to it too; the
-- offboarding transaction binds the (tenant, environment) scope before each shred.
GRANT SELECT ON tenant_keks TO ironauth_control;
GRANT UPDATE (wrapped_kek, status, destroyed_at) ON tenant_keks TO ironauth_control;
