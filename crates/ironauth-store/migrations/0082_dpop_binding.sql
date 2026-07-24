-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- DPoP sender-constrained token binding at issuance (RFC 9449, issue #368 PR2).
--
-- A DPoP proof presented at the token endpoint binds the issued token(s) to the
-- thumbprint (RFC 7638 jkt) of the client's proof key: the access token carries a
-- cnf.jkt confirmation (an at+jwt claim), and the opaque access token and the
-- refresh family record that same jkt so a resource-server verify (a later
-- follow-up) and the refresh-grant enforcement (PR3) can require a matching proof.
-- This migration adds the storage for the two reference-token forms; the at+jwt
-- carries its binding in the signed cnf claim and needs no column.
--
-- Both columns are NULLABLE and default to SQL NULL: NULL means a plain bearer
-- token (no DPoP proof was presented), which is the unchanged behavior for every
-- existing row and every token issued without a proof. Binding is OPPORTUNISTIC,
-- so a token is bound ONLY when a valid proof accompanied its issuance.
--
-- Row level security is INHERITED unchanged: both columns live on tables that are
-- already (tenant, environment)-scoped with forced row-level security
-- (opaque_access_tokens in 0012_opaque_access_tokens.sql, refresh_families in
-- 0016_refresh_tokens.sql). No new table, no new policy, no new grant, no scope
-- CHECK change. Every statement is additive, so this migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- The RFC 7638 JWK thumbprint (jkt) of the DPoP proof key the opaque access token
-- is bound to (RFC 9449). NULL for a plain bearer token (no proof presented). When
-- set, a resource server that verifies this token must require a DPoP proof whose
-- key thumbprint equals this value.
ALTER TABLE opaque_access_tokens ADD COLUMN dpop_jkt text;

-- ---------------------------------------------------------------------------
-- The RFC 7638 JWK thumbprint (jkt) of the DPoP proof key the refresh family is
-- bound to (RFC 9449). NULL for an unbound (bearer) family. When set, the
-- refresh-token grant (a later change) must require a matching DPoP proof to
-- rotate the family and re-binds the rotated token to the same key.
ALTER TABLE refresh_families ADD COLUMN dpop_jkt text;
