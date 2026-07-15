-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Admin user CRUD, lifecycle states, and external IDs (issue #52).
--
-- This is the foundational root of M6: it promotes the deliberately-minimal
-- bootstrap `users` directory (issue #20/#48) into a full control-plane managed
-- entity without weakening any of its isolation or PII guarantees. It is a purely
-- additive EXPAND: new nullable columns, a state column with a safe 'active'
-- default, a partial unique index, and a set of grants. No prior-release binary
-- reads the new columns, and every existing row keeps a valid state (the default),
-- so the change is safe under a rolling deploy.
--
-- Four things the management plane needs, all folded onto `users`:
--
--   1. A first-class LIFECYCLE STATE (`state`): active, blocked, disabled,
--      pending_verification, scheduled_offboarding, or the deleted tombstone. The
--      transitions are a real state machine enforced in the repository (only valid
--      transitions apply, an invalid one is refused fail closed), and the
--      session-ending transitions (block, disable, delete) cascade to the user's
--      sessions and refresh families and publish to the unified session-ended
--      fan-out (issue #35), so a lifecycle change actually ends live sessions and
--      notifies relying parties, never leaves them stranded.
--
--   2. An EXTERNAL ID for correlation with the tenant's own systems (CRM, HR,
--      billing). It is a lookup key, so it follows the same BLIND-INDEX pattern the
--      login handle does (issue #48): `external_id_bidx` is a deterministic
--      per-tenant keyed HMAC that equality lookups query, and `external_id_sealed`
--      is the AEAD-sealed value for display and round-trip. The plaintext external
--      id never lands in a column, so a database dump reveals neither the value nor
--      a reversible hash. A partial UNIQUE index gives an external id at most one
--      user per (tenant, environment), so a second claim of the same external id is
--      refused, and because the index is scope-keyed the same external-id string in
--      two tenants maps to two different users with no cross-tenant collision.
--
--   3. Offboarding schedule (`scheduled_offboarding_at`): the timestamp a
--      scheduled-offboarding user is disabled at, executed idempotently by a worker
--      and audited.
--
--   4. The mutation timestamp (`updated_at`) and the soft-delete tombstone
--      (`deleted_at`): a deleted user is retained as a tombstone (so the
--      append-only audit log's references to it stay legible and the login lookup
--      still resolves it as absent) and reads as a uniform not-found thereafter.
--
-- Migration safety obligation (see migrate.rs): `users` is already a tenant-scoped
-- table with forced row-level security and the (tenant, environment) policy from
-- issue #20, so this migration adds no new table and no new policy. It DOES widen
-- access: the control plane (ironauth_control) now manages users, so it is granted
-- SELECT/INSERT and a COLUMN-SCOPED UPDATE on `users` (never a table-wide UPDATE,
-- the #31 least-privilege lesson), and SELECT/INSERT on the envelope key tables so
-- it can seal, blind-index, and open user PII exactly as the data plane does. The
-- data plane also gains the column-scoped UPDATE (the scheduled-offboarding worker
-- and the data-plane fence read/advance the same columns).

-- ---------------------------------------------------------------------------
-- The lifecycle state, defaulting to 'active' so every pre-existing bootstrap row
-- is a live account with no backfill. The closed set is pinned by a CHECK; the
-- repository owns the transition state machine.
ALTER TABLE users
    ADD COLUMN state text NOT NULL DEFAULT 'active';

ALTER TABLE users
    ADD CONSTRAINT users_state_valid
        CHECK (state IN (
            'active', 'blocked', 'disabled', 'pending_verification',
            'scheduled_offboarding', 'deleted'
        ));

-- The external-id blind index (the equality-lookup key) and the sealed external id
-- (for display and round-trip), plus the DEK version that sealed it. All nullable:
-- an external id is optional, and a user without one has all three NULL.
ALTER TABLE users
    ADD COLUMN external_id_bidx        bytea,
    ADD COLUMN external_id_sealed      bytea,
    ADD COLUMN external_id_dek_version integer;

-- The scheduled-offboarding instant (NULL unless the user is scheduled for
-- offboarding), the last-mutation instant, and the soft-delete tombstone. Both
-- timestamps come from the application clock seam on write.
ALTER TABLE users
    ADD COLUMN scheduled_offboarding_at timestamptz,
    ADD COLUMN updated_at               timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN deleted_at               timestamptz;

-- An external id claims AT MOST ONE user per (tenant, environment): a second claim
-- of the same external id fails as a unique violation. Partial (only non-NULL blind
-- indexes are constrained), so the many users without an external id are unaffected.
-- Scope-keyed, so the SAME external-id string in two tenants is two distinct rows.
CREATE UNIQUE INDEX users_external_id_bidx_unique
    ON users (tenant_id, environment_id, external_id_bidx)
    WHERE external_id_bidx IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Grants.
--
-- The control plane now manages users end to end: it reads and lists them, creates
-- them (with a caller-supplied id), and mutates their lifecycle. It gets SELECT and
-- INSERT plus a COLUMN-SCOPED UPDATE over exactly the columns the lifecycle,
-- external-id link/unlink, soft-delete, and profile-update paths rewrite. Never the
-- login handle or password hash (a user's handle and credential are set once at
-- create), and never a table-wide UPDATE (the #31 lesson). `claims_sealed` is
-- included so a PATCH can update the standard-claim profile, re-sealed under the
-- row's existing DEK version.
GRANT SELECT, INSERT ON users TO ironauth_control;
GRANT UPDATE (
        state, external_id_bidx, external_id_sealed, external_id_dek_version,
        claims_sealed, scheduled_offboarding_at, updated_at, deleted_at
    ) ON users TO ironauth_app, ironauth_control;

-- The control plane seals, blind-indexes, and opens user PII through the envelope
-- substrate (issue #48), so it needs to provision (lazily, on the first user in a
-- scope) and read the scope's KEK and DEK, exactly as the data plane does. SELECT
-- and INSERT only: rotation and crypto-shredding stay data-plane / offboarding
-- operations, so no column-scoped UPDATE is granted here.
GRANT SELECT, INSERT ON tenant_keks TO ironauth_control;
GRANT SELECT, INSERT ON tenant_deks TO ironauth_control;
