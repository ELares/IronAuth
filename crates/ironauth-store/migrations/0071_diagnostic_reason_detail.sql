-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Widen the client authentication diagnostics sink for the M9 flow inspector (issue #91).
--
-- The out of band client_auth_diagnostics sink (migration 0013) already records WHY a client
-- authentication failed off the wire (the bounded failure_reason, the assertion header key id
-- and alg) while the wire response stays a uniform, opaque invalid_client. The M9 admin flow
-- inspector needs the SPECIFIC assertion reject reason surfaced (bad signature, expired, clock
-- skew, audience mismatch, unknown kid, disallowed algorithm). The reason itself is a text
-- column, so the newly distinguished reason STRINGS need no schema change; this migration adds
-- only the two DERIVED, NON SECRET fields the richer reasons carry:
--
--   skew_seconds: the bounded clock skew bucket, in seconds. How far the presented exp / nbf
--     fell OUTSIDE the tolerance window, computed against the application clock. Signed
--     (positive = expired past the window, negative = not yet valid), clamped to a bounded
--     range in the recorder. It is a COMPUTED integer, never the assertion; NULL unless the
--     reason is an expired or clock skew failure recorded under the verbose verbosity.
--
--   expected: the bounded expectation hint, for example 'kid_not_in_registered_jwks'. A closed
--     set of structural hints (see DiagnosticExpectation), never the JWKS and never a key;
--     NULL unless the relevant reason is recorded under the verbose verbosity.
--
-- Both are NULLABLE and additive: this is an EXPAND. An ALTER TABLE ADD COLUMN preserves the
-- table's existing row level security (ENABLE + FORCE), its tenant isolation policy, its scope
-- nonempty CHECK, its foreign keys, and its indexes, and the table level GRANT SELECT / INSERT
-- / DELETE to ironauth_app already covers columns added later, so the M9 read sees the new
-- columns and the recorder writes them with no further grant. Every existing row back fills to
-- NULL for both (the derived fields were simply not captured before), which the read renders as
-- "no skew bucket" and "no hint", an inert, truthful absence.

ALTER TABLE client_auth_diagnostics
    ADD COLUMN skew_seconds bigint,
    ADD COLUMN expected     text;

-- Reassert the row level security posture for defense in depth (the ALTER preserves it; this
-- makes the invariant explicit in the migration that touches the table, exactly as every scoped
-- table declares it). These statements are idempotent no ops when already in force.
ALTER TABLE client_auth_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_auth_diagnostics FORCE ROW LEVEL SECURITY;
