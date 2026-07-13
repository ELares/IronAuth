-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The recorded authentication event: honest acr, amr, and auth_time (issue #14).
--
-- The ID token's acr, amr, and auth_time must be DERIVED from what actually
-- happened at login, never asserted from a request parameter. #20's session
-- already records auth_time; this migration adds the recorded authentication
-- METHOD(s) alongside it, freezes that authentication context onto the
-- single-use authorization code at issuance, and adds the client's
-- require_auth_time registration flag. All three changes are additive column
-- expands on existing tenant-scoped tables (no new table, no policy change):
-- the (tenant, environment) isolation, forced row-level security, and audited
-- write paths those tables already carry apply unchanged.
--
--   1. sessions.auth_methods: the RFC 8176 method tokens recorded at login (the
--      bootstrap password login is `pwd`). This is the recorded authentication
--      event's method half; auth_time (already present) is its time half. amr
--      and the achieved acr are DERIVED from these methods, never stored as a
--      claim and never taken from the request.
--   2. authorization_codes.auth_methods and .auth_time: the authentication
--      context FROZEN onto the code at issuance, so the token endpoint mints an
--      ID token that reflects the login event as it stood when the code was
--      issued (not a later, possibly-expired session read). auth_time here is
--      nullable and set ONLY when the ID token must carry it (the request asked
--      for max_age, or the client registered require_auth_time); a NULL means
--      the claim is omitted. The recorded methods are always frozen so amr and
--      acr can be derived at mint.
--   3. clients.require_auth_time: the per-client registration flag that forces
--      auth_time into every ID token for the client, independent of max_age.
--      Defaults false, so every existing client is unchanged.
--
-- Backfill honesty: `auth_methods` defaults to `pwd` because the only login
-- path that exists is the bootstrap password login, so any row created before
-- this column existed was, by construction, a password authentication. Every
-- write path after this migration sets the value explicitly.

-- The recorded authentication method(s) for a session: space-separated RFC 8176
-- method tokens (the bootstrap password login records `pwd`). The single source
-- the ID token's amr and acr are derived from.
ALTER TABLE sessions
    ADD COLUMN auth_methods text NOT NULL DEFAULT 'pwd';

-- The authentication context frozen onto a single-use code at issuance:
--   * auth_methods: the recorded method tokens (always set), so the token
--     endpoint can derive amr and the achieved acr at mint time.
--   * auth_time: the recorded authentication instant, set ONLY when the ID
--     token must carry the auth_time claim (max_age requested or the client
--     registered require_auth_time). NULL means the claim is omitted. When set,
--     it is the truthful session auth_time, never a request-supplied value.
ALTER TABLE authorization_codes
    ADD COLUMN auth_methods text        NOT NULL DEFAULT 'pwd',
    ADD COLUMN auth_time    timestamptz;

-- The client's require_auth_time registration flag. When true, every ID token
-- issued to the client carries auth_time even without a max_age request.
-- Additive and safe for the old binary: defaults false, so every client created
-- before this migration keeps the Core default (auth_time only when max_age is
-- requested).
ALTER TABLE clients
    ADD COLUMN require_auth_time boolean NOT NULL DEFAULT false;
