-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-client Front-Channel Logout registration for OAuth clients (issue #39).
--
-- OpenID Connect Front-Channel Logout 1.0 lets an OP notify a relying party of a
-- logout by loading, in a hidden iframe during the end_session flow, a URI the RP
-- registered ahead of time. Two per-client registration values back that:
--
--   * frontchannel_logout_uri: the RP endpoint the OP loads in an iframe on logout.
--     NULL (the default) means the client did NOT opt in, so it participates in NO
--     front-channel logout. This is the per-client opt-in half of the two-part gate
--     (the environment-level oidc.frontchannel_logout_enabled flag is the other):
--     with NO registered URI, a client is never sent a front-channel iframe even in
--     an environment where the feature is enabled.
--
--   * frontchannel_logout_session_required: whether the OP MUST append iss and the
--     RP's OWN per-(client, session) sid (issue #32) to the iframe URI, so the RP
--     can tell WHICH of its sessions to clear. Defaults to false (the OP appends
--     neither), matching the OIDC Front-Channel Logout 1.0 default.
--
-- Additive and safe for the old binary: frontchannel_logout_uri defaults to NULL and
-- frontchannel_logout_session_required to false, so every client created before this
-- migration participates in no front-channel logout, and every existing INSERT path
-- (which names neither column) is unchanged. These are columns on the already
-- tenant-isolated clients table: its ENABLE + FORCE row-level security, the
-- (tenant, environment) isolation policy, and the nonempty-scope CHECK from 0001 all
-- apply to these columns unchanged, so they add NO new isolation obligation and create
-- no new table.
ALTER TABLE clients
    ADD COLUMN frontchannel_logout_uri text,
    ADD COLUMN frontchannel_logout_session_required boolean NOT NULL DEFAULT false;

-- Column-scoped data-plane write grant (issue #31 lesson, NEVER a table-wide UPDATE).
-- Migration 0018 revoked the table-wide UPDATE ironauth_app held and re-granted a
-- COLUMN-SCOPED UPDATE over exactly the data-plane-owned clients columns; a table-level
-- UPDATE would auto-cover every future column, so a new column stays app-unwritable
-- until deliberately granted. The client-registration path writes exactly these two
-- columns on the data plane, so grant UPDATE on exactly them and nothing else. The
-- control plane keeps its read-only SELECT on clients (granted in 0018); it is not
-- granted UPDATE here because front-channel registration is a data-plane concern.
GRANT UPDATE (frontchannel_logout_uri, frontchannel_logout_session_required)
    ON clients TO ironauth_app;
