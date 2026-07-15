-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Registered post-logout redirect URIs for OAuth clients (issue #33).
--
-- OpenID Connect RP-Initiated Logout 1.0 lets a relying party send the end user's
-- browser to the end_session_endpoint with a post_logout_redirect_uri, and the OP
-- redirects back to it AFTER ending the session. RFC 9700 section 2.1 requires that
-- value to be matched by EXACT STRING against a set the client registered ahead of
-- time (the same discipline the authorization redirect_uris column from 0008 already
-- enforces): an unregistered target is an open redirector the logout would hand an
-- attacker-chosen destination, and the state parameter along with it. This column is
-- the registered set the exact-string comparator checks a presented
-- post_logout_redirect_uri against, and the OP redirects ONLY on an exact match with
-- a cryptographically verifiable id_token_hint binding the request to this client.
--
-- Additive and safe for the old binary: the set defaults to the empty array, so every
-- client created before this migration keeps an empty registered set (no
-- post_logout_redirect_uri is ever honored for it, the logout simply renders a neutral
-- logged-out page), and every existing INSERT path (which names no
-- post_logout_redirect_uris column) is unchanged. This is a column on the already
-- tenant-isolated clients table: its ENABLE + FORCE row-level security, the
-- (tenant, environment) isolation policy, and the nonempty-scope CHECK from 0001 all
-- apply to this column unchanged, so it adds NO new isolation obligation and creates no
-- new table.
ALTER TABLE clients
    ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

-- Column-scoped data-plane write grant (issue #31 lesson, NEVER a table-wide UPDATE).
-- Migration 0018 revoked the table-wide UPDATE ironauth_app held and re-granted a
-- COLUMN-SCOPED UPDATE over exactly the data-plane-owned clients columns; a table-level
-- UPDATE would auto-cover every future column, so a new column stays app-unwritable
-- until deliberately granted. The end_session endpoint (and the client-registration
-- path) writes this column on the data plane, so grant UPDATE on exactly it and nothing
-- else. The control plane keeps its read-only SELECT on clients (granted in 0018); it
-- is not granted UPDATE here because post-logout registration is a data-plane concern.
GRANT UPDATE (post_logout_redirect_uris) ON clients TO ironauth_app;
