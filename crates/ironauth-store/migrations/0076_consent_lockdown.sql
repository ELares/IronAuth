-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Revocable remembered consent and first-party client classification (issue #88).
--
-- Two additive column expands, both safe for the old binary (each defaults to
-- today's behavior, and no existing write names either column):
--
--   1. consents.revoked_at: a nullable revocation instant. A non-null value means
--      the recorded grant is revoked, so the authorization gate treats it as absent
--      and re-prompts. Self-service revocation (the data plane, which already holds
--      table SELECT on consents) flips exactly this column, so the data-plane role
--      gains a column-scoped UPDATE on it (never a table-wide UPDATE). The revocation
--      SURFACES ship later (PR5); this migration only stores the column and grants
--      the data-plane write. Admin (control-plane) revocation lands in PR5 together
--      with the SELECT the control plane needs to target a row, so its grants are
--      deliberately deferred rather than shipped dead here.
--   2. clients.first_party: an explicit first-party classification an admin sets on
--      provisioning. The lockdown gate keys off it (PR3): a first-party client is
--      carved out of the third-party admin-consent requirement. Control-plane
--      write-only, exactly like quarantined and verified_at (0018), so a compromised
--      or buggy data-plane path can never self-classify a client as first-party.
--      This migration only stores and selects the column; PR3 enforces it.
--
-- Row-level security is already ENABLED and FORCED on both tables (0006), and both
-- changes are additive columns under the existing (tenant, environment) isolation
-- policy, so no new policy is needed. The column-grant split matches the
-- established least-privilege pattern (0010, 0016, 0018).

-- ---------------------------------------------------------------------------
-- 1. Revocable remembered consent (issue #88).
--
-- A recorded consent row is never deleted; it is REVOKED by stamping revoked_at
-- from the application clock seam. NULL (the default) is an active grant; a
-- non-null value is a revoked grant the authorization gate reads as absent and
-- re-prompts against. Additive nullable column, safe for the old binary.
ALTER TABLE consents ADD COLUMN revoked_at timestamptz;

-- The data-plane role already holds table-level SELECT and INSERT (0006) plus
-- column-level UPDATE on granted_scope (0010) and expires_at (0016). Self-service
-- revocation (PR5) flips revoked_at, so the role needs UPDATE on that column too.
-- The guarded revoke UPDATE reads the row (WHERE (subject, client) plus RETURNING
-- id) under the data-plane's existing table SELECT. Least privilege is preserved:
-- still no table-wide UPDATE, only these enumerated columns.
GRANT UPDATE (revoked_at) ON consents TO ironauth_app;

-- Admin (control-plane) revocation is intentionally NOT granted here. The control
-- plane holds no SELECT on consents, so a column-scoped UPDATE alone would be a
-- dead grant (the revoke reads the row to target it). PR5, which adds the admin
-- revocation surface, grants the control plane the SELECT it needs and the
-- UPDATE (revoked_at) together, so the grant is coherent and testable when it
-- first has a caller.

-- ---------------------------------------------------------------------------
-- 2. First-party client classification (issue #88).
--
-- An explicit identity property an admin sets when provisioning a client. The
-- lockdown gate (PR3) carves a first-party client out of the third-party
-- admin-consent requirement, so this is a security-relevant classification.
-- Additive and safe for the old binary: defaults to false (every client stays
-- third-party until deliberately classified).
ALTER TABLE clients ADD COLUMN first_party boolean NOT NULL DEFAULT false;

-- Control-plane write-only, exactly like the quarantined and verified_at columns
-- (0018): the control plane classifies a client as first-party through this grant.
-- The data plane is deliberately NOT granted UPDATE on first_party, so it stays
-- app-unwritable. Migration 0018 REVOKEd the data plane's table-wide UPDATE on
-- clients and re-granted a column-scoped one that enumerates only the
-- data-plane-owned columns; because first_party is absent from that list, the data
-- plane cannot write it, which is the whole point (a compromised or buggy
-- data-plane path can never self-classify a client as first-party and defeat the
-- lockdown gate). The control plane already holds table-level SELECT on clients
-- (0018), which covers this additive column for the verify-and-classify WHERE.
GRANT UPDATE (first_party) ON clients TO ironauth_control;
