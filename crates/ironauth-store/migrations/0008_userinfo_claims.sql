-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The end-user standard-claim store backing UserInfo (issue #15).
--
-- UserInfo (OIDC Core 5.3) returns the standard claim SETS a scope maps to
-- (profile, email, address, phone per Core 5.4) plus any requested through the
-- claims request parameter (Core 5.5). Those claims need per-user VALUES, and the
-- bootstrap user directory (issue #20) stored only the login handle and the
-- Argon2id verifier. This migration adds a single additive column that holds the
-- user's standard claim values as a JSON object.
--
--   users.claims: a JSON object of OIDC standard claim name -> value (for example
--   {"email": "a@b.test", "email_verified": true, "name": "Ada"}). Stored as text
--   (a JSON document), not jsonb, so the data-plane read decodes it in the OIDC
--   layer with the crate's existing serde_json rather than adding the sqlx json
--   feature to the store. UserInfo releases only the members a granted scope or an
--   explicit claims request selects; a member absent from the object is simply
--   omitted (an unsatisfiable voluntary claim is never an error). `sub` is NEVER
--   read from here: it is always derived through the one shared subject function.
--
-- Additive and safe for the old binary: the column defaults to the empty JSON
-- object '{}', so every user created before this migration (and the existing
-- register path, which does not name the column) is unchanged and simply carries
-- no releasable standard claims. This is a minimal slice of the M-series identity
-- model (no verified claims, no per-claim provenance, no update path); the full
-- model replaces it later, keeping the claims-parameter pipeline additive.
--
-- No new table and no policy change: `users` already ENABLEs and FORCEs row-level
-- security keyed on the (tenant, environment) session variables (issue #20), and a
-- column add inherits that isolation and the existing SELECT/INSERT grant to
-- ironauth_app unchanged.

ALTER TABLE users
    ADD COLUMN claims text NOT NULL DEFAULT '{}';

-- ---------------------------------------------------------------------------
-- The persisted `claims` request parameter (OIDC Core 5.5).
--
-- The `claims` parameter is presented once, at the authorization request, but its
-- `userinfo` member is applied later when UserInfo is called (Core 5.5). The
-- authorization endpoint therefore parses and validates it, then FREEZES a
-- canonical JSON form onto BOTH the grant and the single-use code at issuance:
--
--   * grants.claims_request: read back by UserInfo, which resolves an access token
--     to its grant, so the `userinfo` member survives from authorization to the
--     UserInfo call.
--   * authorization_codes.claims_request: read back at the token endpoint (with the
--     rest of the code's bindings) so the ID token can honor the `id_token` member
--     at mint time.
--
-- Both are nullable text (a JSON document, decoded in the OIDC layer): NULL means
-- the request carried no `claims` parameter. Additive and safe for the old binary
-- (the existing issue path names neither column and leaves them NULL).
ALTER TABLE grants
    ADD COLUMN claims_request text;

ALTER TABLE authorization_codes
    ADD COLUMN claims_request text;
