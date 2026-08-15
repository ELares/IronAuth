-- 0143: the per-client token-exchange policy (issue #125, RFC 8693).
--
-- Two switches, both default-deny, both per CLIENT.
--
-- `token_exchange_impersonation_allowed` gates the one exchange mode that erases the
-- caller. Delegation records the actor in the issued token's `act` chain, so a resource
-- server can see that A is acting for B and decide accordingly; impersonation deliberately
-- does not, which is precisely what makes it dangerous and precisely what makes it useful
-- for a support tool. The 2026 Zitadel token-exchange privilege escalation is what this
-- column is for: a client that could exchange a token it did not receive, for one naming
-- somebody else, with nothing recording that it had done so.
--
-- `token_exchange_refresh_allowed` gates issuing a REFRESH token from an exchange. RFC 8693
-- permits it; defaulting it on would be a lifetime-laundering primitive, because a
-- short-lived access token could be traded for a credential that outlives it and can be
-- traded again. An operator who wants that has to say so per client.
--
-- DEFAULT false on both means a client row created before this migration, or by any code
-- path that does not name the columns, lands on the SAFE side. The booleans are phrased as
-- `_allowed` rather than `_restricted` for the same reason 0142 chose `allow_bearer_tokens`:
-- the false value has to be the strict one, or a forgotten default and a missing column
-- both fail open.
--
-- Expand phase: additive with defaults, so an old reader that never selects these columns
-- is unaffected and a rolling upgrade is safe in both directions.

ALTER TABLE clients
    ADD COLUMN token_exchange_impersonation_allowed boolean NOT NULL DEFAULT false,
    ADD COLUMN token_exchange_refresh_allowed boolean NOT NULL DEFAULT false;

-- The CONTROL plane may flip them; nobody else may.
--
-- The data plane READS both on every exchange and must never be able to write either: a
-- data-plane compromise that could set the impersonation flag would be able to switch off
-- the very control these columns exist to enforce, which is the escalation this whole
-- grant is designed against.
--
-- Column scoped, as every grant on this table is, and granted in the SAME migration that
-- adds the columns (the 0115 lesson: a column that ships with a reader, a setter, and no
-- grant sits at its default on every deployment and nothing surfaces it).
GRANT UPDATE (token_exchange_impersonation_allowed, token_exchange_refresh_allowed)
    ON clients TO ironauth_control;

COMMENT ON COLUMN clients.token_exchange_impersonation_allowed IS
    'Issue #125: when true, this client may use the RFC 8693 token-exchange grant in '
    'IMPERSONATION mode, presenting a subject token issued to another client and '
    'receiving one that names only the subject, with no `act` chain recording the '
    'caller. False (the default) refuses that exchange. Delegation and downscoping are '
    'unaffected. Every use is audited as token_exchange.issue.';

COMMENT ON COLUMN clients.token_exchange_refresh_allowed IS
    'Issue #125: when true, this client may request a refresh token as the '
    'requested_token_type of an RFC 8693 exchange. False (the default) refuses it, so an '
    'exchange cannot turn a short-lived access token into a longer-lived credential.';
